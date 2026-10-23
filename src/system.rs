use anyhow::{bail, ensure, Context, Result};
use fs2::FileExt;
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::{
    fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    process::CommandExt,
};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const LABEL: &str = "io.github.lucasuiii.netmoat";
pub const ANCHOR: &str = "com.apple/netmoat_0000000000000000";
pub const PF: &str = "/sbin/pfctl";
pub const LAUNCHCTL: &str = "/bin/launchctl";
pub const FORMAT: &str = "netmoat-service-v2";

#[derive(Clone)]
pub struct Paths {
    pub home: PathBuf,
    pub run: PathBuf,
    pub plist: PathBuf,
    pub launcher: PathBuf,
    pub public_status: PathBuf,
    pub owner: u32,
}
impl Paths {
    pub fn system() -> Self {
        Self {
            home: "/Library/Application Support/NetMoat".into(),
            run: "/private/var/run/netmoat-service".into(),
            plist: format!("/Library/LaunchDaemons/{LABEL}.plist").into(),
            launcher: "/usr/local/bin/netmoat".into(),
            public_status: "/private/var/run/netmoat-public/status.json".into(),
            owner: 0,
        }
    }
    pub fn secure(&self, path: &Path, directory: bool) -> Result<()> {
        let m = fs::symlink_metadata(path)
            .with_context(|| format!("Cannot inspect {}", path.display()))?;
        ensure!(
            !m.file_type().is_symlink()
                && (if directory { m.is_dir() } else { m.is_file() })
                && m.uid() == self.owner
                && m.mode() & 0o022 == 0,
            "Unsafe service path: {}",
            path.display()
        );
        Ok(())
    }
    pub fn mkdir(&self, path: &Path) -> Result<()> {
        match fs::create_dir(path) {
            Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e.into()),
        }
        self.secure(path, true)
    }
    pub fn read(&self, path: &Path, max: u64) -> Result<Vec<u8>> {
        self.secure(path, false)?;
        read_limited(path, max)
    }
    pub fn installed(&self) -> Result<()> {
        self.secure(&self.home, true)?;
        let value: serde_json::Value =
            serde_json::from_slice(&self.read(&self.home.join("installed.json"), 65536)?)?;
        ensure!(
            [Some(FORMAT), Some("netmoat-service-v1")].contains(&value["format"].as_str()),
            "Unrecognized installation"
        );
        Ok(())
    }
    pub fn lock(&self, management: bool, wait: Duration) -> Result<File> {
        let base = if management { &self.home } else { &self.run };
        self.mkdir(base)?;
        let path = base.join(if management {
            "management.lock"
        } else {
            "lock"
        });
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        self.secure(&path, false)?;
        let deadline = Instant::now() + wait;
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => return Ok(file),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(100))
                }
                Err(e) => return Err(e).context("Another NetMoat operation is still running"),
            }
        }
    }
}

pub fn read_limited(path: &Path, max: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?
        .take(max + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= max, "File exceeds size limit");
    Ok(bytes)
}

pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32, durable: bool) -> Result<()> {
    let parent = path.parent().context("Missing parent directory")?;
    let mut temp = tempfile::Builder::new()
        .prefix(".netmoat-")
        .tempfile_in(parent)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temp.write_all(bytes)?;
    if durable {
        temp.as_file().sync_all()?;
    }
    temp.persist(path).map_err(|e| e.error)?;
    if durable {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

pub fn write_json<T: Serialize>(path: &Path, value: &T, durable: bool) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    atomic_write(path, &bytes, 0o600, durable)
}

pub fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

#[derive(Clone, Debug)]
pub struct Output {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}
impl Output {
    pub fn checked(self, program: &str) -> Result<Self> {
        ensure!(
            self.code == 0,
            "{} failed ({}): {}",
            program,
            self.code,
            self.stderr.trim()
        );
        Ok(self)
    }
}
pub trait Runner: Send + Sync {
    fn run(&self, program: &str, args: &[&str], timeout: Duration) -> Result<Output>;
    fn enable(&self, mut log: &File) -> Result<()> {
        let out = self.run(PF, &["-E"], Duration::from_secs(10))?;
        log.write_all(out.stdout.as_bytes())?;
        log.write_all(out.stderr.as_bytes())?;
        log.sync_all()?;
        out.checked(PF)?;
        Ok(())
    }
}
pub struct RealRunner;

fn wait_child(child: &mut Child, timeout: Duration) -> std::io::Result<Option<ExitStatus>> {
    // Authorization helpers may block SIGCHLD in the inherited signal mask.
    // Poll waitpid through std instead of depending on delivery of that signal.
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        std::thread::sleep(remaining.min(Duration::from_millis(10)));
    }
}

fn drain(reader: impl Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(1_048_577).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 1_048_576,
        "Command output exceeds size limit"
    );
    Ok(bytes)
}
impl Runner for RealRunner {
    fn enable(&self, log: &File) -> Result<()> {
        // pfctl writes its reference directly into the durable log descriptor.
        // A kill between command completion and parsing cannot lose the token.
        let mut child = Command::new(PF)
            .arg("-E")
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("LC_ALL", "C")
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log.try_clone()?))
            .process_group(0)
            .spawn()?;
        let status = wait_child(&mut child, Duration::from_secs(10));
        if !matches!(status, Ok(Some(_))) {
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.wait();
        }
        log.sync_all()?;
        ensure!(
            status?.map(|s| s.success()).unwrap_or(false),
            "PF enable failed or timed out; log retained"
        );
        Ok(())
    }
    fn run(&self, program: &str, args: &[&str], timeout: Duration) -> Result<Output> {
        let mut child = Command::new(program)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("LC_ALL", "C")
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .with_context(|| format!("Cannot start {program}"))?;
        let out = child.stdout.take().context("Missing stdout")?;
        let err = child.stderr.take().context("Missing stderr")?;
        let out = std::thread::spawn(move || drain(out));
        let err = std::thread::spawn(move || drain(err));
        let waited = wait_child(&mut child, timeout);
        let timed_out = !matches!(waited, Ok(Some(_)));
        if timed_out {
            // This process group was created above and contains only this command.
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.wait();
        }
        let stdout = out
            .join()
            .map_err(|_| anyhow::anyhow!("Output reader failed"))??;
        let stderr = err
            .join()
            .map_err(|_| anyhow::anyhow!("Error reader failed"))??;
        let status = waited.context("Cannot wait for command")?;
        if timed_out {
            bail!("{program} timed out; child process group terminated");
        }
        Ok(Output {
            code: status.and_then(|s| s.code()).unwrap_or(-1),
            stdout: String::from_utf8(stdout).context("Non-UTF8 command output")?,
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }
}

pub fn unblock_signals() -> Result<()> {
    // The launch environment may inherit a blocked SIGTERM/SIGINT mask.
    let result = unsafe {
        let mut signals: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut signals);
        libc::sigaddset(&mut signals, libc::SIGTERM);
        libc::sigaddset(&mut signals, libc::SIGINT);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &signals, std::ptr::null_mut())
    };
    ensure!(result == 0, "Cannot unblock service signals: {result}");
    Ok(())
}

pub fn call(runner: &dyn Runner, program: &str, args: &[&str]) -> Result<Output> {
    runner
        .run(program, args, Duration::from_secs(15))?
        .checked(program)
}

pub fn job_plist(binary: &Path, home: &Path) -> String {
    fn xml(path: &Path) -> String {
        path.to_string_lossy()
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{LABEL}</string>
<key>ProgramArguments</key><array><string>{}</string><string>service</string><string>run</string></array>
<key>WorkingDirectory</key><string>{}</string>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>10</integer><key>ExitTimeOut</key><integer>30</integer>
<key>ProcessType</key><string>Background</string><key>Umask</key><integer>63</integer>
</dict></plist>
"#,
        xml(binary),
        xml(home)
    )
}
