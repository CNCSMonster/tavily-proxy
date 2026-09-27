mod handler;

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail};
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

use tavily_proxy::config::Config;
use tavily_proxy::core::ProxyCore;
use tavily_proxy::service;

/// Cap on a single request body. Tavily payloads are a few KiB; the limit exists
/// so an unauthenticated peer cannot make the proxy buffer unbounded input.
const MAX_BODY_BYTES: usize = 1024 * 1024;

const USAGE: &str = "\
tavily-proxy — Tavily API 中转服务

USAGE:
    tavily-proxy [serve] [--foreground|--background] [--config <path>]
    tavily-proxy status  [--config <path>]
    tavily-proxy stop    [--config <path>]
    tavily-proxy restart [--config <path>]

COMMANDS:
    serve       运行代理服务（默认前台）
    status      查看后台服务状态
    stop        停止后台服务
    restart     重启后台服务（= stop + serve --background）

OPTIONS:
    -f, --foreground     前台运行（默认）
    -b, --background     后台运行（setsid 脱离终端；不是 systemd 服务）
    -c, --config <path>  配置文件路径（默认 $TAVILY_PROXY_CONFIG 或 ./config.toml）
    -h, --help           显示本帮助

服务只往 stdout 写日志；落哪个文件、要不要轮转，由运行环境决定（见 README「日志」）。
";

enum Command {
    Serve { background: bool },
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
            "serve" | "status" | "stop" | "restart" if command.is_none() => command = Some(arg),
            other if other.starts_with('-') => bail!("unknown option {other}"),
            other => bail!("unknown command {other}"),
        }
    }

    if foreground && background {
        bail!("--foreground and --background are mutually exclusive");
    }

    let command = match command.as_deref() {
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
    info!(
        tavily_keys = core.key_pool.total_keys(),
        available = core.key_pool.available_keys(),
        "key pool initialized"
    );
    log_filter_chain(&core);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    runtime.block_on(async move {
        // Bind before publishing the pid: a port clash must not leave a pid file
        // pointing at a process that never served.
        let listener = TcpListener::bind(&listen)
            .await
            .with_context(|| format!("failed to bind {listen}"))?;

        let pid = std::process::id();
        service::claim_pid(pid, config_path)?;
        info!(%listen, pid, "tavily-proxy listening");

        let app = build_router(core);
        let result = axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await;

        service::revoke_pid_file_if_owned(pid);
        result.with_context(|| format!("server stopped with an error on {listen}"))
    })
}

/// Say plainly whether filtering is on: an absent `[filter]` section is easy to
/// mistake for "checks are running" when reading a config file.
fn log_filter_chain(core: &ProxyCore) {
    if core.filters.is_empty() {
        info!("content safety checks are disabled (no enabled [[filter.rules]])");
    } else {
        info!(
            rules = ?core.filters.names(),
            block_threshold = core.filters.block_threshold(),
            output_block = ?core.filters.output_block(),
            scan_raw_content = core.filters.scan_raw_content(),
            "content safety chain initialized"
        );
    }
}

fn build_router(core: Arc<ProxyCore>) -> Router {
    Router::new()
        .route("/search", post(handler::handle_search))
        .route("/extract", post(handler::handle_extract))
        .route("/health", get(handler::handle_health))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(core)
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
