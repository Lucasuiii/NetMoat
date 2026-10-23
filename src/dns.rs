use crate::config::{global_address, Config, Policy, MAX_JSON};
use crate::system::{now, write_json, Paths, Runner};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub addresses: Vec<String>,
    pub resolved_at: f64,
}
pub type Records = BTreeMap<String, Record>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsState {
    pub enabled: bool,
    pub stale_hosts: Vec<String>,
}

#[derive(Deserialize)]
struct Answer {
    #[serde(rename = "type")]
    kind: u16,
    data: String,
}
#[derive(Deserialize)]
struct Reply {
    #[serde(rename = "Status")]
    status: u32,
    #[serde(rename = "Answer")]
    answers: Option<Vec<Answer>>,
}

pub fn parse_reply(raw: &[u8], v6: bool) -> Result<Vec<String>> {
    ensure!(raw.len() <= 65536, "DNS reply exceeds size limit");
    let reply: Reply = serde_json::from_slice(raw).context("Invalid DNS reply structure")?;
    ensure!(reply.status == 0, "DNS resolver reported failure");
    let mut result = Vec::new();
    for answer in reply.answers.unwrap_or_default() {
        if answer.kind != if v6 { 28 } else { 1 } {
            continue;
        }
        let address: IpAddr = answer.data.parse().context("Invalid DNS address")?;
        ensure!(
            address.is_ipv6() == v6 && global_address(address),
            "DNS returned a non-global or mismatched address"
        );
        result.push(address.to_string());
    }
    ensure!(result.len() <= 4096, "Too many DNS addresses");
    Ok(result)
}

fn lookup(runner: &dyn Runner, host: &str, v6: bool, proxy: &str) -> Result<Vec<String>> {
    // Hostnames/proxy have already been validated; no shell or direct fallback.
    let url = format!(
        "https://cloudflare-dns.com/dns-query?name={host}&type={}",
        if v6 { "AAAA" } else { "A" }
    );
    let out = runner
        .run(
            "/usr/bin/curl",
            &[
                "--silent",
                "--show-error",
                "--fail",
                "--proto",
                "=https",
                "--proxy",
                proxy,
                "--noproxy",
                "",
                "--connect-timeout",
                "3",
                "--max-time",
                "5",
                "--max-filesize",
                "65536",
                "--header",
                "accept: application/dns-json",
                &url,
            ],
            Duration::from_secs(7),
        )?
        .checked("DNS query")?;
    parse_reply(out.stdout.as_bytes(), v6)
}

pub fn load(paths: &Paths) -> Result<Records> {
    let path = paths.home.join("dns-cache.json");
    if !path.exists() {
        return Ok(Records::new());
    }
    let records: Records = serde_json::from_slice(&paths.read(&path, MAX_JSON)?)
        .context("Invalid DNS cache structure")?;
    ensure!(records.len() <= 256, "DNS cache has too many hosts");
    for (host, record) in &records {
        crate::config::validate_hosts(std::slice::from_ref(host))?;
        ensure!(
            record.resolved_at.is_finite()
                && record.resolved_at >= 0.0
                && record.resolved_at <= now() + 300.0,
            "Invalid DNS cache time"
        );
        ensure!(
            record.addresses.len() <= 4096 && !record.addresses.is_empty(),
            "Invalid DNS cache addresses"
        );
        for address in &record.addresses {
            ensure!(
                global_address(address.parse()?),
                "Unsafe cached DNS address"
            );
        }
    }
    Ok(records)
}

pub fn effective(config: &Config, records: &Records, timestamp: f64) -> Result<(Policy, DnsState)> {
    let mut policy = config.static_policy()?;
    let hosts = config.hosts();
    let mut state = DnsState {
        enabled: !hosts.is_empty(),
        stale_hosts: Vec::new(),
    };
    let interval = config
        .dns
        .as_ref()
        .map(|d| d.refresh_seconds)
        .unwrap_or(300) as f64;
    for host in hosts {
        let record = records
            .get(&host)
            .context("DNS address unavailable; previous PF rules retained")?;
        ensure!(
            !record.addresses.is_empty(),
            "DNS address unavailable; previous PF rules retained"
        );
        for value in &record.addresses {
            let address: IpAddr = value.parse()?;
            ensure!(global_address(address), "Unsafe cached DNS address");
            policy.targets.insert(address.into());
        }
        if timestamp - record.resolved_at > 3.0 * interval {
            state.stale_hosts.push(host);
        }
    }
    ensure!(
        policy.targets.len() <= 4096,
        "Combined target count exceeds limit"
    );
    Ok((policy, state))
}

pub struct Cache {
    pub records: Records,
    next: Instant,
    key: String,
    pub load_error: Option<String>,
}
impl Cache {
    pub fn new(paths: &Paths) -> Self {
        let (records, load_error) = match load(paths) {
            Ok(r) => (r, None),
            Err(e) => (Records::new(), Some(e.to_string())),
        };
        Self {
            records,
            next: Instant::now(),
            key: String::new(),
            load_error,
        }
    }

    pub fn refresh(&mut self, config: &Config, paths: &Paths, runner: &dyn Runner) -> Result<()> {
        let hosts = config.hosts();
        if hosts.is_empty() {
            return Ok(());
        }
        let dns = config.dns.as_ref().context("Missing DNS settings")?;
        let key = serde_json::to_string(&(&hosts, &dns.proxy, dns.refresh_seconds))?;
        if self.key == key && Instant::now() < self.next {
            return Ok(());
        }
        let timestamp = now();
        let mut changed = false;
        // At most four simultaneous hosts; each needs successful A and AAAA replies.
        for batch in hosts.chunks(4) {
            let results = std::thread::scope(|scope| {
                let handles = batch
                    .iter()
                    .map(|host| {
                        scope.spawn(move || -> Result<(String, Vec<String>)> {
                            let mut values = lookup(runner, host, false, &dns.proxy)?;
                            values.extend(lookup(runner, host, true, &dns.proxy)?);
                            values.sort();
                            values.dedup();
                            ensure!(!values.is_empty(), "DNS reply has no usable addresses");
                            Ok((host.clone(), values))
                        })
                    })
                    .collect::<Vec<_>>();
                handles
                    .into_iter()
                    .map(|handle| {
                        handle
                            .join()
                            .unwrap_or_else(|_| Err(anyhow::anyhow!("DNS worker failed")))
                    })
                    .collect::<Vec<_>>()
            });
            for (host, addresses) in results.into_iter().flatten() {
                self.records.insert(
                    host,
                    Record {
                        addresses,
                        resolved_at: timestamp,
                    },
                );
                changed = true;
            }
        }
        // Bound the cache and avoid persisting unrelated/removed hostnames.
        self.records.retain(|host, _| hosts.contains(host));
        self.key = key;
        self.next = Instant::now() + Duration::from_secs(dns.refresh_seconds);
        if changed {
            write_json(&paths.home.join("dns-cache.json"), &self.records, true)?;
            self.load_error = None;
        }
        Ok(())
    }
}
