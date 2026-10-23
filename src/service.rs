use crate::config::{digest, valid_digest, Config, MAX_JSON};
use crate::dns::{self, Cache, DnsState};
use crate::pf::Guard;
use crate::system::{
    atomic_write, call, job_plist, now, read_limited, write_json, Paths, Runner, ANCHOR, FORMAT,
    LABEL, LAUNCHCTL,
};
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use signal_hook::{
    consts::{SIGINT, SIGTERM},
    iterator::Signals,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct State {
    pub anchor: String,
    pub pid: u32,
    pub state: String,
    pub updated_at: f64,
    pub config_sha256: String,
    pub policy_sha256: String,
    pub interfaces: Vec<String>,
    pub target_count: usize,
    pub module_count: usize,
    pub active_modules: usize,
    pub dns: Option<DnsState>,
    pub error: Option<String>,
    pub backend: String,
    pub version: String,
}

#[derive(Serialize)]
pub struct Status {
    pub installed: bool,
    pub loaded: bool,
    pub autostart_enabled: bool,
    pub rules_verified: bool,
    pub state_fresh: bool,
    pub checked_at: f64,
    pub state: State,
    pub counters: BTreeMap<String, u64>,
    pub error: Option<String>,
}
#[derive(Serialize)]
pub struct Snapshot {
    pub configuration: Config,
    pub configuration_sha256: String,
    pub status: Status,
}

pub fn publish(paths: &Paths, state: &State) -> Result<()> {
    // Public heartbeat intentionally contains no domains, addresses, interface names,
    // proxy settings, module names, or raw error messages.
    let value = json!({"format": "netmoat-status-v1", "state": state.state, "updated_at": state.updated_at,
        "backend": state.backend, "version": state.version, "configuration_sha256": state.config_sha256,
        "rules_verified": state.state == "rules_loaded", "target_count": state.target_count,
        "active_modules": state.active_modules, "stale_host_count": state.dns.as_ref().map(|d| d.stale_hosts.len()).unwrap_or(0)});
    paths.secure(
        paths
            .public_status
            .parent()
            .context("Missing status parent")?,
        true,
    )?;
    atomic_write(
        &paths.public_status,
        &serde_json::to_vec(&value)?,
        0o644,
        false,
    )
}

pub struct Backend<'a> {
    pub paths: Paths,
    pub runner: &'a dyn Runner,
}
impl Backend<'_> {
    pub fn guard(&self) -> Guard<'_> {
        Guard {
            paths: &self.paths,
            runner: self.runner,
            anchor: ANCHOR,
        }
    }
    fn target(&self) -> String {
        format!("system/{LABEL}")
    }
    fn loaded(&self) -> Result<bool> {
        Ok(self
            .runner
            .run(
                LAUNCHCTL,
                &["print", &self.target()],
                Duration::from_secs(10),
            )?
            .code
            == 0)
    }
    fn config(&self) -> Result<(Config, String)> {
        let bytes = self
            .paths
            .read(&self.paths.home.join("policy.json"), MAX_JSON)?;
        Ok((Config::parse(&bytes)?, digest(&bytes)))
    }
    fn state(&self) -> Result<State> {
        let path = self.paths.run.join("state.json");
        if !path.exists() {
            return Ok(State::default());
        }
        Ok(serde_json::from_slice(&self.paths.read(&path, MAX_JSON)?)?)
    }

    pub fn status(&self) -> Status {
        let installed = self.paths.home.exists();
        let mut result = Status {
            installed,
            loaded: false,
            autostart_enabled: false,
            rules_verified: false,
            state_fresh: false,
            checked_at: now(),
            state: State::default(),
            counters: BTreeMap::new(),
            error: None,
        };
        let checked = (|| -> Result<()> {
            if !installed {
                return Ok(());
            }
            self.paths.installed()?;
            self.paths.mkdir(&self.paths.run)?;
            result.loaded = self.loaded()?;
            let overrides = call(self.runner, LAUNCHCTL, &["print-disabled", "system"])?;
            let disabled = overrides
                .stdout
                .lines()
                .any(|s| s.contains(&format!("\"{LABEL}\"")) && s.contains("=> true"));
            result.autostart_enabled = self.paths.plist.exists()
                && !disabled
                && !self.paths.home.join("disabled").exists();
            result.state = self.state()?;
            result.state_fresh =
                result.state.updated_at <= now() + 5.0 && now() - result.state.updated_at <= 90.0;
            if !result.loaded || !result.state_fresh || result.state.state != "rules_loaded" {
                return Ok(());
            }
            let (config, sha) = self.config()?;
            if sha != result.state.config_sha256 {
                return Ok(());
            }
            let records = if config.hosts().is_empty() {
                dns::Records::new()
            } else {
                dns::load(&self.paths)?
            };
            let (policy, dns_state) = dns::effective(&config, &records, now())?;
            result.state.dns = Some(dns_state);
            if result.state.policy_sha256 != policy.fingerprint() {
                return Ok(());
            }
            result.rules_verified = self.guard().readback(&policy)?;
            if result.rules_verified {
                result.counters = self.guard().counts()?;
            }
            Ok(())
        })();
        if let Err(error) = checked {
            result.rules_verified = false;
            result.error = Some(format!("{error:#}"));
        }
        result
    }

    pub fn snapshot(&self) -> Result<Snapshot> {
        self.paths.installed()?;
        // A GUI document and its privileged check must describe one version.
        let _lock = self.paths.lock(true, Duration::from_secs(2))?;
        let (configuration, configuration_sha256) = self.config()?;
        Ok(Snapshot {
            configuration: configuration.editable(),
            configuration_sha256,
            status: self.status(),
        })
    }

    // One iteration is separately testable without signals, live PF, or a live resolver.
    pub fn tick(&self, cache: &mut Cache) -> Result<State> {
        let (config, sha) = self.config()?;
        let editable = config.editable();
        cache.refresh(&config, &self.paths, self.runner)?;
        let (policy, dns) = dns::effective(&config, &cache.records, now())?;
        self.guard().ensure(&policy)?;
        Ok(State {
            anchor: ANCHOR.into(),
            pid: std::process::id(),
            state: "rules_loaded".into(),
            updated_at: now(),
            config_sha256: sha,
            policy_sha256: policy.fingerprint(),
            interfaces: policy.interfaces,
            target_count: policy.targets.len(),
            module_count: editable.modules.as_ref().map(Vec::len).unwrap_or(0),
            active_modules: editable
                .modules
                .iter()
                .flatten()
                .filter(|m| m.enabled)
                .count(),
            dns: Some(dns),
            error: None,
            backend: "rust".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        })
    }

    pub fn run(&self) -> Result<()> {
        self.paths.installed()?;
        let _lock = self.paths.lock(false, Duration::ZERO)?;
        crate::system::unblock_signals()?;
        let mut signals = Signals::new([SIGTERM, SIGINT])?;
        let handle = signals.handle();
        let (send, receive) = mpsc::channel();
        let signal_thread = std::thread::spawn(move || {
            if let Some(signal) = signals.forever().next() {
                let _ = send.send(signal);
            }
        });
        let mut cache = Cache::new(&self.paths);
        let mut previous = State::default();
        let mut signature = String::new();
        let mut last_write = Instant::now() - Duration::from_secs(60);
        loop {
            if self.paths.home.join("disabled").exists() {
                break;
            }
            let state = match self.tick(&mut cache) {
                Ok(state) => state,
                Err(error) => State {
                    state: "degraded".into(),
                    error: Some(format!("{error:#}").chars().take(1000).collect()),
                    updated_at: now(),
                    pid: std::process::id(),
                    backend: "rust".into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    ..previous.clone()
                },
            };
            let mut comparable = state.clone();
            comparable.updated_at = 0.0;
            let current = serde_json::to_string(&comparable)?;
            if signature != current || last_write.elapsed() >= Duration::from_secs(30) {
                // Transient heartbeat: atomic, but no forced disk synchronization.
                // Write failures leave PF intact and are retried on the next tick.
                match write_json(&self.paths.run.join("state.json"), &state, false)
                    .and_then(|_| publish(&self.paths, &state))
                {
                    Ok(()) => {
                        signature = current;
                        last_write = Instant::now();
                    }
                    Err(error) => {
                        eprintln!("Cannot update service status; rules retained: {error:#}")
                    }
                }
            }
            previous = state;
            match receive.recv_timeout(Duration::from_secs(10)) {
                Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => (),
            }
        }
        handle.close();
        let _ = signal_thread.join();
        // Never remove rules on a signal, panic, or error. Explicit stop owns cleanup.
        Ok(())
    }

    fn wait_verified(&self, expected: Option<&str>, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let state = self.state().unwrap_or_default();
            if state.state == "rules_loaded"
                && expected
                    .map(|sha| sha == state.config_sha256)
                    .unwrap_or(true)
                && self.status().rules_verified
            {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        bail!("Service policy was not verified before the deadline; inspect status")
    }

    pub fn configure(&self, path: &Path, expected: &str) -> Result<()> {
        self.paths.installed()?;
        valid_digest(expected)?;
        let config = Config::parse(&read_limited(path, MAX_JSON)?)?;
        let _lock = self.paths.lock(true, Duration::ZERO)?;
        let config_path = self.paths.home.join("policy.json");
        let previous = self.paths.read(&config_path, MAX_JSON)?;
        ensure!(
            digest(&previous) == expected,
            "Configuration conflict: refresh before saving; no changes made"
        );
        let mut bytes = serde_json::to_vec_pretty(&config)?;
        bytes.push(b'\n');
        let sha = digest(&bytes);
        if sha == expected {
            return Ok(());
        }
        let running = self.loaded()?;
        // The exact intended bytes define this transaction, not a subsequent re-read.
        atomic_write(
            &self.paths.home.join("policy.previous.json"),
            &previous,
            0o600,
            true,
        )?;
        atomic_write(&config_path, &bytes, 0o600, true)?;
        if !running {
            return Ok(());
        }
        if let Err(error) = self.wait_verified(Some(&sha), Duration::from_secs(60)) {
            if self.rollback_if_current(&sha, &previous)? {
                let restored = self
                    .wait_verified(Some(expected), Duration::from_secs(30))
                    .is_ok();
                bail!(
                    "{error:#}; previous configuration restored; restoration verified: {restored}"
                );
            }
            bail!("{error:#}; a newer configuration exists and was not overwritten");
        }
        Ok(())
    }

    pub fn rollback_if_current(&self, candidate: &str, previous: &[u8]) -> Result<bool> {
        let path = self.paths.home.join("policy.json");
        if digest(&self.paths.read(&path, MAX_JSON)?) != candidate {
            return Ok(false);
        }
        atomic_write(&path, previous, 0o600, true)?;
        Ok(true)
    }

    fn start_inner(&self) -> Result<()> {
        let disabled = self.paths.home.join("disabled");
        if disabled.exists() {
            fs::remove_file(disabled)?;
        }
        call(self.runner, LAUNCHCTL, &["enable", &self.target()])?;
        if !self.loaded()? {
            call(
                self.runner,
                LAUNCHCTL,
                &[
                    "bootstrap",
                    "system",
                    self.paths.plist.to_str().context("Invalid plist path")?,
                ],
            )?;
        }
        call(self.runner, LAUNCHCTL, &["kickstart", &self.target()])?;
        self.wait_verified(None, Duration::from_secs(60))
    }
    pub fn start(&self) -> Result<()> {
        self.paths.installed()?;
        let _lock = self.paths.lock(true, Duration::ZERO)?;
        self.start_inner()
    }

    fn stop_inner(&self) -> Result<()> {
        atomic_write(&self.paths.home.join("disabled"), b"stopped\n", 0o600, true)?;
        call(self.runner, LAUNCHCTL, &["disable", &self.target()])?;
        if self.loaded()? {
            self.runner
                .run(
                    LAUNCHCTL,
                    &["bootout", &self.target()],
                    Duration::from_secs(45),
                )?
                .checked(LAUNCHCTL)?;
        }
        let _daemon_lock = self.paths.lock(false, Duration::from_secs(30))?;
        self.guard().cleanup()?;
        let state = State {
            anchor: ANCHOR.into(),
            state: "stopped".into(),
            updated_at: now(),
            backend: "rust".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            ..State::default()
        };
        write_json(&self.paths.run.join("state.json"), &state, false)?;
        publish(&self.paths, &state)
    }
    pub fn stop(&self) -> Result<()> {
        self.paths.installed()?;
        let _lock = self.paths.lock(true, Duration::ZERO)?;
        self.stop_inner()
    }

    fn stage_binary(&self) -> Result<()> {
        let binary = std::env::current_exe()?;
        let bytes = read_limited(&binary, 64 * MAX_JSON)?;
        atomic_write(&self.paths.home.join("netmoat"), &bytes, 0o755, true)?;
        atomic_write(
            &self.paths.plist,
            job_plist(&self.paths.home.join("netmoat"), &self.paths.home).as_bytes(),
            0o644,
            true,
        )?;
        let launcher = format!(
            "#!/bin/sh\nexec \"{}/netmoat\" \"$@\"\n",
            self.paths.home.display()
        );
        atomic_write(&self.paths.launcher, launcher.as_bytes(), 0o755, true)?;
        write_json(
            &self.paths.home.join("installed.json"),
            &json!({"format": FORMAT, "backend": "rust",
            "version": env!("CARGO_PKG_VERSION"), "installed_at": now()}),
            true,
        )
    }

    pub fn install(&self, path: &Path) -> Result<()> {
        let bytes = read_limited(path, MAX_JSON)?;
        Config::parse(&bytes)?;
        ensure!(
            !self.paths.home.exists()
                && !self.paths.plist.exists()
                && !self.paths.launcher.symlink_metadata().is_ok(),
            "Installation or conflicting path already exists; use service upgrade"
        );
        for path in [&self.paths.home, &self.paths.plist, &self.paths.launcher] {
            self.paths
                .secure(path.parent().context("Missing parent")?, true)?;
        }
        self.paths.mkdir(&self.paths.home)?;
        let _lock = self.paths.lock(true, Duration::ZERO)?;
        atomic_write(&self.paths.home.join("policy.json"), &bytes, 0o600, true)?;
        self.stage_binary()?;
        self.start_inner()
    }

    pub fn upgrade(&self) -> Result<()> {
        self.paths.installed()?;
        self.paths.secure(&self.paths.plist, false)?;
        self.paths.secure(&self.paths.launcher, false)?;
        let (config, _) = self.config()?;
        config.editable().validate()?;
        let _lock = self.paths.lock(true, Duration::ZERO)?;
        let backup = self.paths.home.join("upgrade-backup");
        ensure!(
            !backup.exists(),
            "Unfinished upgrade backup exists; inspect it before retrying"
        );
        self.paths.mkdir(&backup)?;
        for (name, path) in [
            ("job.plist", &self.paths.plist),
            ("launcher", &self.paths.launcher),
            ("installed.json", &self.paths.home.join("installed.json")),
        ] {
            atomic_write(
                &backup.join(name),
                &self.paths.read(path, 64 * MAX_JSON)?,
                0o600,
                true,
            )?;
        }
        let binary = self.paths.home.join("netmoat");
        if binary.exists() {
            atomic_write(
                &backup.join("netmoat"),
                &self.paths.read(&binary, 64 * MAX_JSON)?,
                0o700,
                true,
            )?;
        }
        let was_loaded = self.loaded()?;
        let was_disabled = self.paths.home.join("disabled").exists();
        let attempt = (|| -> Result<()> {
            // Legacy Python may clean its rules here; migration has a documented gap.
            if was_loaded {
                self.runner
                    .run(
                        LAUNCHCTL,
                        &["bootout", &self.target()],
                        Duration::from_secs(45),
                    )?
                    .checked(LAUNCHCTL)?;
            }
            let daemon_lock = self.paths.lock(false, Duration::from_secs(30))?;
            self.stage_binary()?;
            // Force a fresh heartbeat before trusting the new process.
            let state_path = self.paths.run.join("state.json");
            if state_path.exists() {
                fs::remove_file(state_path)?;
            }
            drop(daemon_lock);
            if !was_disabled {
                self.start_inner()?;
            }
            Ok(())
        })();
        if let Err(error) = attempt {
            if self.loaded().unwrap_or(false) {
                let _ = self.runner.run(
                    LAUNCHCTL,
                    &["bootout", &self.target()],
                    Duration::from_secs(45),
                );
            }
            let _daemon_lock = self.paths.lock(false, Duration::from_secs(30))?;
            for (name, path, mode) in [
                ("job.plist", self.paths.plist.clone(), 0o644),
                ("launcher", self.paths.launcher.clone(), 0o755),
                (
                    "installed.json",
                    self.paths.home.join("installed.json"),
                    0o600,
                ),
            ] {
                atomic_write(
                    &path,
                    &self.paths.read(&backup.join(name), 64 * MAX_JSON)?,
                    mode,
                    true,
                )?;
            }
            if backup.join("netmoat").exists() {
                atomic_write(
                    &binary,
                    &self.paths.read(&backup.join("netmoat"), 64 * MAX_JSON)?,
                    0o755,
                    true,
                )?;
            }
            drop(_daemon_lock);
            if was_loaded && !was_disabled {
                let _ = call(self.runner, LAUNCHCTL, &["enable", &self.target()]);
                let _ = call(
                    self.runner,
                    LAUNCHCTL,
                    &[
                        "bootstrap",
                        "system",
                        self.paths.plist.to_str().context("Invalid plist path")?,
                    ],
                );
            }
            bail!("Upgrade failed; previous launch configuration restored, backup retained: {error:#}");
        }
        // Remove old installed Python backend only after successful native verification.
        for name in ["netmoat.py", "netmoat_service.py"] {
            let path = self.paths.home.join(name);
            if path.exists() {
                self.paths.secure(&path, false)?;
                fs::remove_file(path)?;
            }
        }
        let pycache = self.paths.home.join("__pycache__");
        if pycache.exists() {
            self.paths.secure(&pycache, true)?;
            fs::remove_dir_all(pycache)?;
        }
        fs::remove_dir_all(backup)?;
        Ok(())
    }

    pub fn uninstall(&self) -> Result<()> {
        self.paths.installed()?;
        let _lock = self.paths.lock(true, Duration::ZERO)?;
        self.stop_inner()?;
        let plist = String::from_utf8(self.paths.read(&self.paths.plist, MAX_JSON)?)?;
        let launcher = String::from_utf8(self.paths.read(&self.paths.launcher, MAX_JSON)?)?;
        ensure!(
            plist.contains(LABEL)
                && launcher.contains(&format!("{}/netmoat", self.paths.home.display())),
            "Refusing to remove unrelated launcher/job"
        );
        fs::remove_file(&self.paths.plist)?;
        fs::remove_file(&self.paths.launcher)?;
        if self.paths.public_status.exists() {
            self.paths.secure(&self.paths.public_status, false)?;
            fs::remove_file(&self.paths.public_status)?;
        }
        fs::remove_dir_all(&self.paths.run)?;
        fs::remove_dir_all(&self.paths.home)?;
        Ok(())
    }
}
