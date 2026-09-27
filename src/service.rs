//! User-level background lifecycle for the proxy.
//!
//! The binary re-executes itself with `setsid` so it survives the shell that
//! launched it, publishes its own pid file, and appends logs under the XDG state
//! directory. No service manager unit, no sudo: everything lives in the user's
//! own home directory, so deploying on a server means copying one directory and
//! running one command.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::config::Config;

const APP_DIR: &str = "tavily-proxy";
const PID_FILE: &str = "tavily-proxy.pid";
const LOG_FILE: &str = "tavily-proxy.log";

/// Upper bound on waiting for the child's startup verdict. A parent that gave up
/// earlier would report failure while the child was still legally starting.
pub const BACKGROUND_START_BUDGET: Duration = Duration::from_secs(10);
const BACKGROUND_START_POLL: Duration = Duration::from_millis(100);
const STOP_STEP_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// Application state directory (`XDG_STATE_HOME` or `~/.local/state`), holding
/// the log. Never derived from `XDG_RUNTIME_DIR`.
pub fn state_dir() -> PathBuf {
    match env_dir("XDG_STATE_HOME") {
        Some(root) => root.join(APP_DIR),
        None => home_dir().join(".local").join("state").join(APP_DIR),
    }
}

/// Process-scoped directory for the pid file (`XDG_RUNTIME_DIR` or the state
/// dir's `runtime/` subdirectory).
pub fn runtime_dir() -> PathBuf {
    match env_dir("XDG_RUNTIME_DIR") {
        Some(root) => root.join(APP_DIR),
        None => state_dir().join("runtime"),
    }
}

pub fn pid_path() -> PathBuf {
    runtime_dir().join(PID_FILE)
}

pub fn log_path() -> PathBuf {
    state_dir().join(LOG_FILE)
}

fn env_dir(name: &str) -> Option<PathBuf> {
    let value = std::env::var_os(name)?;
    if value.is_empty() {
        return None;
    }
    Some(PathBuf::from(value))
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Publish `pid` as the running instance, refusing to clobber another live one.
///
/// The config path is recorded alongside the pid: one state directory holds one
/// instance, so a command aimed at a *different* config has to be able to tell
/// that this pid file is not its business. Without that, `--config b.toml
/// restart` would silently kill the instance serving `a.toml`.
pub fn claim_pid(pid: u32, config: &Path) -> Result<()> {
    if let Some(other) = running_pid()
        && other != pid
    {
        let owner = read_pid_file()
            .and_then(|(_, config)| config)
            .map(|config| config.display().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        bail!(
            "tavily-proxy is already running (pid {other}, config {owner}); \
             use `tavily-proxy restart` with that same --config, or point XDG_STATE_HOME/XDG_RUNTIME_DIR \
             elsewhere to run a second instance"
        );
    }
    let path = pid_path();
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    fs::write(&path, pid_file_contents(pid, config))
        .with_context(|| format!("failed to write pid file {}", path.display()))?;
    enforce_mode(&path, 0o600)?;
    Ok(())
}

/// Contents of the pid file: the pid, then the config it was started with.
pub fn pid_file_contents(pid: u32, config: &Path) -> String {
    format!("{pid}\n{}\n", canonical_config(config).display())
}

/// Parse a pid file. A file without the config line is from an older build, and
/// reports `None` rather than inventing an owner.
pub fn parse_pid_file(text: &str) -> Option<(u32, Option<PathBuf>)> {
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    let pid = lines.next()?.parse().ok()?;
    Some((pid, lines.next().map(PathBuf::from)))
}

/// Is this pid file ours to act on?
///
/// An unknown owner (a file written before the config line existed) counts as
/// "not ours": refusing to signal is recoverable, signalling the wrong process is
/// not.
pub fn owner_matches(recorded: Option<&Path>, requested: &Path) -> bool {
    matches!(recorded, Some(recorded) if recorded == requested)
}

fn canonical_config(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| absolute_path(path))
}

fn read_pid_file() -> Option<(u32, Option<PathBuf>)> {
    parse_pid_file(&fs::read_to_string(pid_path()).ok()?)
}

/// Remove the pid file only if it still records our own pid; a failed start must
/// not delete the record of a healthy instance that published after us.
pub fn revoke_pid_file_if_owned(pid: u32) {
    let path = pid_path();
    if read_pid_file().is_some_and(|(recorded, _)| recorded == pid) {
        let _ = fs::remove_file(&path);
    }
}

pub fn running_pid() -> Option<u32> {
    let (pid, _) = read_pid_file()?;
    process_exists(pid).then_some(pid)
}

pub fn status(config: &Path) -> Result<()> {
    match read_pid_file() {
        Some((pid, owner)) if process_exists(pid) => {
            println!("tavily-proxy is running");
            println!("  pid: {pid}");
            println!(
                "  config: {}",
                owner
                    .as_deref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "unknown (pid file written by an older build)".to_string())
            );
            println!("  pid_file: {}", pid_path().display());
            println!("  log: {}", log_path().display());
            if !owner_matches(owner.as_deref(), &canonical_config(config)) {
                println!(
                    "  note: this is not the instance for {}",
                    canonical_config(config).display()
                );
            }
        }
        _ => println!("tavily-proxy is not running"),
    }
    Ok(())
}

/// Start a detached copy of this binary and wait for a real startup verdict.
pub fn start_background(config_path: &Path, cfg: &Config) -> Result<()> {
    // Resolve the listen address here so a typo fails with a clear message
    // instead of as "the background process exited early".
    let listen = cfg.server.listen.clone();
    let probe_addr = listen
        .to_socket_addrs()
        .with_context(|| format!("invalid listen address {listen:?}"))?
        .next()
        .with_context(|| format!("listen address {listen:?} resolved to no socket address"))?;

    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    let config_path = absolute_path(config_path);

    ensure_private_dir(&runtime_dir())?;
    ensure_private_dir(&state_dir())?;
    refuse_if_running()?;

    let log_path = log_path();
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("failed to open log {}", log_path.display()))?;
    enforce_mode(&log_path, 0o600)?;
    let log_for_stderr = log
        .try_clone()
        .with_context(|| format!("failed to clone log {}", log_path.display()))?;

    let mut command = Command::new(exe);
    command
        .arg("--config")
        .arg(&config_path)
        .arg("serve")
        .arg("--foreground")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_for_stderr));
    detach(&mut command);

    let mut child = command
        .spawn()
        .context("failed to start tavily-proxy in background")?;

    match confirm_background_start(
        BACKGROUND_START_BUDGET,
        BACKGROUND_START_POLL,
        &mut || {
            child
                .try_wait()
                .map(|status| status.map(|status| status.to_string()))
                .context("failed to inspect background process")
        },
        &|| health_ok(probe_addr),
    )? {
        BackgroundStart::Started => {}
        BackgroundStart::Exited(status) => {
            // The child publishes its own pid file and revokes it when startup
            // fails, so the parent only observes — a second write here could
            // resurrect the pid of a process that already exited.
            revoke_pid_file_if_owned(child.id());
            bail!(
                "tavily-proxy background process exited early with {status}; see {}",
                log_path.display()
            );
        }
        BackgroundStart::Undecided => {
            bail!(
                "背景进程 pid {} 仍在运行，但 {}s 内 /health 没有给出就绪信号：结果不可判定，按失败处理。\n\
                 进程可能只是启动得慢，稍后才就绪：先执行 `tavily-proxy status` 再决定是否重试，不要直接再起一次。\n\
                 查看 {}，必要时执行 `tavily-proxy stop`",
                child.id(),
                BACKGROUND_START_BUDGET.as_secs(),
                log_path.display()
            );
        }
    }

    println!("tavily-proxy started in background");
    println!("  listen: {listen}");
    println!("  pid: {}", child.id());
    println!("  pid_file: {}", pid_path().display());
    println!("  log: {}", log_path.display());
    println!("Use `tavily-proxy serve --foreground` to run in the foreground.");
    Ok(())
}

pub fn shutdown_background(config: &Path) -> Result<()> {
    let path = pid_path();
    let Some((pid, owner)) = read_pid_file() else {
        // Either no file at all, or one this build cannot parse: in both cases
        // there is nothing here we are entitled to signal.
        if path.exists() {
            bail!(
                "refusing to act on {}: it does not record a pid this build understands. \
                 Inspect it and remove it by hand if it is stale.",
                path.display()
            );
        }
        println!("tavily-proxy is not running");
        return Ok(());
    };

    if !process_exists(pid) {
        let _ = fs::remove_file(&path);
        println!("tavily-proxy is not running (removed stale pid file for pid {pid})");
        return Ok(());
    }

    // The one dangerous case: a live process this command was not aimed at.
    if !owner_matches(owner.as_deref(), &canonical_config(config)) {
        bail!(
            "refusing to stop pid {pid}: it was started with config {}, not {}. \
             Re-run with that --config, or use a different XDG_STATE_HOME/XDG_RUNTIME_DIR for this instance.",
            owner
                .as_deref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "unknown (pid file written by an older build)".to_string()),
            canonical_config(config).display()
        );
    }

    if !terminate_process_confirmed(pid, STOP_STEP_TIMEOUT)? {
        bail!(
            "tavily-proxy pid={pid} 未能在 SIGTERM/SIGKILL 后退出；为保留诊断未删除 pid 文件。\
             请手动确认后处理：kill -9 {pid}"
        );
    }

    let _ = fs::remove_file(&path);
    println!("tavily-proxy stopped (pid {pid})");
    Ok(())
}

pub fn restart_background(config_path: &Path, cfg: &Config) -> Result<()> {
    // Stops only the instance that this config started; if another config owns the
    // pid file this fails before anything is signalled.
    shutdown_background(config_path)?;
    start_background(config_path, cfg)
}

/// How far the background child's startup got, as the parent can observe it.
#[derive(Debug, PartialEq, Eq)]
enum BackgroundStart {
    Started,
    Exited(String),
    Undecided,
}

/// Poll the two real signals until one decides the outcome.
///
/// "Still alive after N ms" is not success: a child that dies later (port in
/// use, config rejected) would leave a pid file pointing at a corpse. Exit is
/// checked first because a dead process outranks any positive signal. Both
/// observers are injected so tests never spawn processes.
fn confirm_background_start(
    budget: Duration,
    poll_interval: Duration,
    child_exited: &mut impl FnMut() -> Result<Option<String>>,
    ready: &impl Fn() -> bool,
) -> Result<BackgroundStart> {
    let deadline = Instant::now() + budget;
    loop {
        if let Some(status) = child_exited()? {
            return Ok(BackgroundStart::Exited(status));
        }
        if ready() {
            return Ok(BackgroundStart::Started);
        }
        if Instant::now() >= deadline {
            return Ok(BackgroundStart::Undecided);
        }
        thread::sleep(poll_interval);
    }
}

/// Is the instance already answering `/health` on `addr`?
///
/// A successful connect plus a parsed `{"status":"ok"}` proves the child bound
/// the listener *and* reached its request loop, which is the strongest signal
/// available without a side channel.
fn health_ok(addr: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, PROBE_TIMEOUT) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(PROBE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(PROBE_TIMEOUT));
    if stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut response = String::new();
    if stream.read_to_string(&mut response).is_err() {
        return false;
    }
    response.contains("\"ok\"")
}

fn refuse_if_running() -> Result<()> {
    if let Some(pid) = running_pid() {
        bail!("tavily-proxy is already running (pid {pid}); use `tavily-proxy restart`");
    }
    Ok(())
}

/// Send SIGTERM, then SIGKILL if the process lingers. `Ok(false)` means it is
/// still alive and the caller must fail loudly rather than claim a clean stop.
fn terminate_process_confirmed(pid: u32, step_timeout: Duration) -> Result<bool> {
    if !process_exists(pid) {
        return Ok(true);
    }
    terminate_process(pid)?;
    if wait_for_exit(pid, step_timeout) {
        return Ok(true);
    }
    force_kill_process(pid)?;
    Ok(wait_for_exit(pid, step_timeout))
}

fn wait_for_exit(pid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if !process_exists(pid) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(unix)]
fn process_exists(pid: u32) -> bool {
    if pid == 0 || is_zombie(pid) {
        return false;
    }
    // SAFETY: signal 0 performs error checking only; it never delivers a signal.
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
fn process_exists(_pid: u32) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn is_zombie(pid: u32) -> bool {
    let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    // `stat` is "pid (comm) state ..." and `comm` may contain spaces or parens,
    // so the state letter is the first field after the closing paren.
    match stat.rsplit_once(')') {
        Some((_, rest)) => rest.trim_start().starts_with('Z'),
        None => false,
    }
}

#[cfg(not(target_os = "linux"))]
fn is_zombie(_pid: u32) -> bool {
    false
}

#[cfg(unix)]
fn terminate_process(pid: u32) -> Result<()> {
    // SAFETY: pid came from our own pid file; SIGTERM is the polite stop.
    if unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) } == -1 {
        // A process that vanished between the check and the signal is already
        // stopped, which is what the caller wanted.
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ESRCH) {
            return Err(err).with_context(|| format!("failed to send SIGTERM to pid {pid}"));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn force_kill_process(pid: u32) -> Result<()> {
    // SAFETY: see `terminate_process`.
    if unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) } == -1 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ESRCH) {
            return Err(err).with_context(|| format!("failed to send SIGKILL to pid {pid}"));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn terminate_process(pid: u32) -> Result<()> {
    bail!("stopping pid {pid} is only implemented on unix")
}

#[cfg(not(unix))]
fn force_kill_process(pid: u32) -> Result<()> {
    bail!("stopping pid {pid} is only implemented on unix")
}

/// Detach the child from the controlling terminal and the current session.
fn detach(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: `setsid` is async-signal-safe and the only call in the child
        // between fork and exec.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(not(unix))]
    let _ = command;
}

fn absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(path)
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("failed to create {}", path.display()))?;
    enforce_mode(path, 0o700)?;
    Ok(())
}

/// chmod, then re-stat through `symlink_metadata` so a swapped symlink cannot
/// make us believe we secured something we did not.
#[cfg(unix)]
fn enforce_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to chmod {mode:#o} {}", path.display()))?;
    let actual = fs::symlink_metadata(path)
        .with_context(|| format!("failed to lstat {} after chmod", path.display()))?
        .mode()
        & 0o777;
    if actual != mode {
        bail!(
            "{} reports mode {actual:#o} after chmod {mode:#o}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn enforce_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}
