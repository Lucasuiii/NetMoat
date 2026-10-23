use crate::config::{targets, Policy};
use crate::system::{atomic_write, call, Paths, Runner, PF};
use anyhow::{bail, ensure, Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;

pub struct Guard<'a> {
    pub paths: &'a Paths,
    pub runner: &'a dyn Runner,
    pub anchor: &'a str,
}

pub fn parse_token(text: &str) -> Result<String> {
    let tokens = text
        .lines()
        .filter_map(|line| {
            let (name, token) = line.split_once(':')?;
            let token = token.trim();
            (name.trim() == "Token"
                && !token.is_empty()
                && token.bytes().all(|c| c.is_ascii_digit()))
            .then(|| token.to_string())
        })
        .collect::<Vec<_>>();
    ensure!(
        tokens.len() == 1,
        "Missing or ambiguous PF enable reference; refusing to acquire another"
    );
    Ok(tokens[0].clone())
}

pub fn parent_loaded(text: &str) -> bool {
    text.lines()
        .any(|line| line.trim_start().starts_with("anchor \"com.apple/*\" "))
}

pub fn counters(text: &str) -> Result<BTreeMap<String, u64>> {
    let mut result = BTreeMap::new();
    let lines = text.lines().collect::<Vec<_>>();
    for (family, label) in [("4", "eg_v4"), ("6", "eg_v6")] {
        let mut total = 0u64;
        let mut found = false;
        for (i, line) in lines.iter().enumerate() {
            if line.contains(&format!("label \"{label}\"")) {
                for next in lines.iter().skip(i + 1).take(4) {
                    if let Some((_, remainder)) = next.split_once("Packets:") {
                        let value: u64 = remainder
                            .split_whitespace()
                            .next()
                            .context("Missing packet count")?
                            .parse()?;
                        total = total.checked_add(value).context("Packet count overflow")?;
                        found = true;
                        break;
                    }
                }
            }
        }
        ensure!(found, "Missing PF packet counters for {label}");
        result.insert(family.to_string(), total);
    }
    Ok(result)
}

impl Guard<'_> {
    pub fn enabled(&self) -> Result<bool> {
        let out = call(self.runner, PF, &["-s", "info"])?;
        for line in out.stdout.lines() {
            if let Some(value) = line.strip_prefix("Status:") {
                return match value.split_whitespace().next() {
                    Some("Enabled") => Ok(true),
                    Some("Disabled") => Ok(false),
                    _ => bail!("Unrecognized PF status"),
                };
            }
        }
        bail!("PF enable status is unavailable")
    }

    pub fn table(&self) -> Result<BTreeSet<ipnet::IpNet>> {
        let text = call(
            self.runner,
            PF,
            &["-a", self.anchor, "-t", "eg_targets", "-T", "show"],
        )?;
        targets(
            &text
                .stdout
                .lines()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>(),
        )
    }

    pub fn readback(&self, policy: &Policy) -> Result<bool> {
        ensure!(
            parent_loaded(&call(self.runner, PF, &["-sr"])?.stdout),
            "System PF parent anchor is absent"
        );
        if !self.enabled()? || self.table()? != policy.targets {
            return Ok(false);
        }
        let rules = call(self.runner, PF, &["-a", self.anchor, "-sr"])?.stdout;
        let canonical = self.paths.run.join("canonical.txt");
        let file = self.paths.run.join("rules.pf");
        Ok(canonical.exists()
            && file.exists()
            && self.paths.read(&canonical, 1_048_576)? == rules.as_bytes()
            && self.paths.read(&file, 1_048_576)? == policy.render().as_bytes())
    }

    fn acquire(&self) -> Result<()> {
        let path = self.paths.run.join("enable.log");
        if path.exists() {
            let text = String::from_utf8(self.paths.read(&path, 65536)?)?;
            parse_token(&text)?;
            if self.enabled()? {
                return Ok(());
            }
            self.release()?;
        }
        // Keep the kernel-issued token even if the process dies before parsing it.
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        self.runner.enable(&file)?;
        parse_token(&String::from_utf8(self.paths.read(&path, 65536)?)?)?;
        Ok(())
    }

    pub fn ensure(&self, policy: &Policy) -> Result<()> {
        ensure!(
            parent_loaded(&call(self.runner, PF, &["-sr"])?.stdout),
            "System PF parent anchor is absent; root rules were not reloaded"
        );
        self.acquire()?;
        let expected = policy.render();
        let canonical = self.paths.run.join("canonical.txt");
        let file = self.paths.run.join("rules.pf");
        // On ordinary ticks only inspect child rules/table. Enable status was checked by acquire.
        let healthy = self.table().map(|t| t == policy.targets).unwrap_or(false)
            && canonical.exists()
            && file.exists()
            && self.paths.read(&file, 1_048_576)? == expected.as_bytes()
            && self.paths.read(&canonical, 1_048_576)?
                == call(self.runner, PF, &["-a", self.anchor, "-sr"])?
                    .stdout
                    .as_bytes();
        if !healthy {
            atomic_write(&file, expected.as_bytes(), 0o600, true)?;
            let filename = file.to_str().context("Non-UTF8 rule path")?;
            call(self.runner, PF, &["-n", "-a", self.anchor, "-f", filename])?;
            call(self.runner, PF, &["-a", self.anchor, "-f", filename])?;
            let loaded = call(self.runner, PF, &["-a", self.anchor, "-sr"])?.stdout;
            ensure!(
                loaded.lines().count() == policy.interfaces.len() * 2,
                "PF rule count readback failed"
            );
            ensure!(self.table()? == policy.targets, "PF target readback failed");
            atomic_write(&canonical, loaded.as_bytes(), 0o600, true)?;
        }
        Ok(())
    }

    pub fn counts(&self) -> Result<BTreeMap<String, u64>> {
        counters(&call(self.runner, PF, &["-a", self.anchor, "-vvsr"])?.stdout)
    }

    fn release(&self) -> Result<()> {
        let path = self.paths.run.join("enable.log");
        if path.exists() {
            let token = parse_token(&String::from_utf8(self.paths.read(&path, 65536)?)?)?;
            call(self.runner, PF, &["-X", &token])?;
            fs::remove_file(path)?;
        }
        Ok(())
    }

    // Deliberately not a Drop implementation. Crashes/signals must retain rules.
    pub fn cleanup(&self) -> Result<()> {
        call(self.runner, PF, &["-a", self.anchor, "-F", "rules"])?;
        call(self.runner, PF, &["-a", self.anchor, "-F", "Tables"])?;
        ensure!(
            call(self.runner, PF, &["-a", self.anchor, "-sr"])?
                .stdout
                .trim()
                .is_empty()
                && call(self.runner, PF, &["-a", self.anchor, "-s", "Tables"])?
                    .stdout
                    .trim()
                    .is_empty(),
            "Cleanup readback failed; PF reference retained"
        );
        self.release()
    }
}
