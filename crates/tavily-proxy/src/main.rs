use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail};
use tokio::net::TcpListener;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use tavily_core::config::Config;
use tavily_core::core::ProxyCore;
use tavily_core::key_pool::mask_key;
use tavily_server::service;

const USAGE: &str = "\
tavily-proxy — Tavily API 中转服务

USAGE:
    tavily-proxy [serve] [--foreground|--background] [--config <path>]
    tavily-proxy check [--config <path>]
    tavily-proxy status  [--config <path>]
    tavily-proxy stop    [--config <path>]
    tavily-proxy restart [--config <path>]

COMMANDS:
    serve       运行代理服务（默认前台）
    check       预检配置：只加载校验，不监听、不联网、不碰 pid（重启前先跑这个）
    status      查看后台服务状态
    stop        停止后台服务
    restart     重启后台服务（= stop + serve --background）

OPTIONS:
    -f, --foreground     前台运行（默认）
    -b, --background     后台运行（setsid 脱离终端；不是 systemd 服务）
    -c, --config <path>  配置文件路径（默认 $TAVILY_PROXY_CONFIG 或 ./config.toml）
    -h, --help           显示本帮助

退出码：check 为 0=配置可用、1=配置有误；其余命令 0=成功。

服务只往 stdout 写日志；落哪个文件、要不要轮转，由运行环境决定（见 README「日志」）。
";

enum Command {
    Serve { background: bool },
    Check,
    Status,
    Stop,
    Restart,
}

struct Cli {
    command: Command,
    config: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let cli = match parse_args(std::env::args().skip(1)) {
        Ok(Some(cli)) => cli,
        Ok(None) => {
            print!("{USAGE}");
            return Ok(());
        }
        Err(err) => {
            eprint!("{USAGE}\nerror: {err}\n");
            std::process::exit(2);
        }
    };

    init_tracing();

    match cli.command {
        Command::Check => check_config(&cli.config),
        Command::Status => service::status(&cli.config),
        Command::Stop => service::shutdown_background(&cli.config),
        Command::Restart => {
            let config = load_config(&cli.config)?;
            service::restart_background(&cli.config, &config)
        }
        Command::Serve { background: true } => {
            let config = load_config(&cli.config)?;
            service::start_background(&cli.config, &config)
        }
        Command::Serve { background: false } => {
            let config = load_config(&cli.config)?;
            serve_foreground(&cli.config, &config)
        }
    }
}

fn load_config(path: &Path) -> anyhow::Result<Config> {
    Config::load(path)
}

/// Log to stdout. The background launcher redirects it to the state dir.
fn init_tracing() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("tavily_proxy=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::stdout().is_terminal())
        .init();
}

/// Parse `args`; `Ok(None)` means help was requested.
///
/// A bare invocation (`tavily-proxy --config x.toml`) is treated as
/// `serve --foreground`, which is what this binary did before it grew commands.
fn parse_args(args: impl Iterator<Item = String>) -> anyhow::Result<Option<Cli>> {
    let mut args = args.peekable();
    let mut command: Option<String> = None;
    let mut background = false;
    let mut foreground = false;
    let mut config: Option<PathBuf> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "-c" | "--config" => {
                let value = args.next().context("--config requires a path")?;
                config = Some(PathBuf::from(value));
            }
            "-f" | "--foreground" => foreground = true,
            "-b" | "--background" => background = true,
            "serve" | "check" | "status" | "stop" | "restart" if command.is_none() => {
                command = Some(arg)
            }
            other if other.starts_with('-') => bail!("unknown option {other}"),
            other => bail!("unknown command {other}"),
        }
    }

    if foreground && background {
        bail!("--foreground and --background are mutually exclusive");
    }

    let command = match command.as_deref() {
        Some("check") => Command::Check,
        Some("status") => Command::Status,
        Some("stop") => Command::Stop,
        Some("restart") => Command::Restart,
        Some("serve") | None => Command::Serve { background },
        Some(other) => bail!("unknown command {other}"),
    };

    let config = config
        .or_else(|| std::env::var("TAVILY_PROXY_CONFIG").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("config.toml"));

    Ok(Some(Cli { command, config }))
}

fn serve_foreground(config_path: &Path, config: &Config) -> anyhow::Result<()> {
    let listen = config.server.listen.clone();
    let core = Arc::new(ProxyCore::from_config(config)?);
    warn_deprecations(config);
    info!(
        tavily_keys = core.key_pool.total_keys(),
        available = core.key_pool.available_keys(),
        upstream_rpm = core.key_pool.rpm(),
        "key pool initialized"
    );
    log_filter_chain(&core);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    runtime.block_on(async move {
        core.auth.start_persistence_worker();

        // Bind before publishing the pid: a port clash must not leave a pid file
        // pointing at a process that never served.
        let listener = TcpListener::bind(&listen)
            .await
            .with_context(|| format!("failed to bind {listen}"))?;

        let pid = std::process::id();
        service::claim_pid(pid, config_path)?;
        info!(%listen, pid, "tavily-proxy listening");

        let app = tavily_server::router(Arc::clone(&core));
        let result = axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await;

        core.auth.flush_quota_sync();
        service::revoke_pid_file_if_owned(pid);
        result.with_context(|| format!("server stopped with an error on {listen}"))
    })
}

/// Warn about deprecated fields the config still uses. Shared by `serve` and
/// `check`: one release of warnings before the fields are refused outright.
fn warn_deprecations(config: &Config) {
    for warning in config.deprecations() {
        warn!("{warning}");
    }
}

/// `check`: run exactly what `serve` runs before it binds — strict parse,
/// validation, filter-chain and key-pool construction — then report and stop.
///
/// No socket, no pid file, no request to Tavily. It exists because a config with
/// a typo in it now refuses to start, so "restart and hope" is no longer a safe
/// upgrade step: run this first (README「升级」).
fn check_config(path: &Path) -> anyhow::Result<()> {
    let built = Config::load(path)
        .and_then(|config| ProxyCore::from_config(&config).map(|core| (config, core)));
    let (config, core) = match built {
        Ok(pair) => pair,
        Err(err) => {
            // `Config::load` scrubs credential-shaped text out of parse errors,
            // so this line is safe to print and safe to leave in a journal.
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    };

    let (rpm, rpm_source) = config.upstream_budget();
    println!("config: {}", path.display());
    println!("listen: {}", config.server.listen);
    println!("upstream rpm: {rpm}（{rpm_source}；0 = 不限速）");
    println!(
        "tavily keys: {} 把（当前可用 {}）",
        core.key_pool.total_keys(),
        core.key_pool.available_keys()
    );
    for key in config.flatten_keys() {
        let limit = match key.max_requests {
            Some(max) => format!("实例累计上限 {max}"),
            None => "实例累计上限 无".to_string(),
        };
        println!("  - {} {limit}", mask_key(&key.key));
    }
    println!("proxy keys: {} 个调用方", config.proxy_keys.len());
    for (index, caller) in config.proxy_keys.iter().enumerate() {
        let label = caller
            .name
            .clone()
            .unwrap_or_else(|| format!("unnamed#{}", index + 1));
        let month = match caller.max_requests_per_month {
            Some(max) => max.to_string(),
            None => "无".to_string(),
        };
        let rpm = match caller.rpm {
            Some(value) => value.to_string(),
            None => "无".to_string(),
        };
        let concurrency = match caller.max_concurrency {
            Some(value) => value.to_string(),
            None => "无".to_string(),
        };
        println!("  - {label}: 月度配额 {month}, rpm {rpm}, 并发 {concurrency}");
    }
    if core.filters.is_empty() {
        println!("filter: 未启用（无 enabled [[filter.rules]]）");
    } else {
        println!("filter: 规则 {:?}", core.filters.names());
    }
    for (label, rules) in &core.filter_routes {
        println!("  - 审查路由 {label}: {rules}");
    }
    for warning in config.deprecations() {
        println!("弃用告警: {warning}");
    }
    println!("check: 通过（未监听、未联网）");
    Ok(())
}

/// Say plainly whether filtering is on: an absent `[filter]` section is easy to
/// mistake for "checks are running" when reading a config file.
fn log_filter_chain(core: &ProxyCore) {
    if core.filters.is_empty() {
        info!("content safety checks are disabled (no enabled [[filter.rules]])");
    } else {
        info!(
            rules = ?core.filters.names(),
            stages = ?core
                .filters
                .stages()
                .iter()
                .map(|stage| stage.as_str())
                .collect::<Vec<_>>(),
            capabilities = ?core
                .filters
                .capabilities()
                .iter()
                .map(|(name, support)| format!("{name}({})", support.describe()))
                .collect::<Vec<_>>(),
            block_threshold = core.filters.block_threshold(),
            output_block = ?core.filters.output_block(),
            scan_raw_content = core.filters.scan_raw_content(),
            "content safety chain initialized"
        );
    }
    // Per-token routes (ISSUE-0006): which token judges with which rules.
    // `key_name` is a label (config name or position) — never the key itself.
    for (label, rules) in &core.filter_routes {
        info!(key_name = %label, rules = %rules, "filter route configured");
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(err) => {
                tracing::warn!(%err, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}
