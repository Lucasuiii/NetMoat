use anyhow::{bail, ensure, Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::net::IpAddr;

pub const MAX_JSON: u64 = 1_048_576;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Module {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub targets: Vec<String>,
    pub hosts: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsSettings {
    pub hosts: Vec<String>,
    pub proxy: String,
    pub refresh_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub interfaces: Vec<String>,
    pub targets: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modules: Option<Vec<Module>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub interfaces: Vec<String>,
    pub targets: BTreeSet<IpNet>,
}

pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn targets(values: &[String]) -> Result<BTreeSet<IpNet>> {
    ensure!(values.len() <= 4096, "At most 4096 targets are allowed");
    values
        .iter()
        .map(|value| {
            ensure!(
                !value.is_empty()
                    && value
                        .bytes()
                        .all(|c| c.is_ascii_hexdigit() || b":./".contains(&c)),
                "Targets must be unscoped numeric IP/CIDR strings"
            );
            let net: IpNet = if value.contains('/') {
                value.parse().context("Invalid target CIDR")?
            } else {
                IpNet::from(value.parse::<IpAddr>().context("Invalid target address")?)
            };
            ensure!(
                net.prefix_len() > 0,
                "Default-route targets are unsupported"
            );
            Ok(net.trunc())
        })
        .collect()
}

pub fn validate_hosts(hosts: &[String]) -> Result<()> {
    ensure!(
        hosts.len() <= 32,
        "At most 32 exact DNS hostnames are allowed"
    );
    for host in hosts {
        ensure!(
            host.len() <= 253 && host.contains('.') && host.is_ascii(),
            "Invalid exact DNS hostname"
        );
        for label in host.split('.') {
            ensure!(
                !label.is_empty()
                    && label.len() <= 63
                    && label.as_bytes()[0].is_ascii_alphanumeric()
                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    && label
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-'),
                "Invalid DNS label"
            );
        }
    }
    Ok(())
}

pub fn validate_proxy(value: &str) -> Result<()> {
    let value = value
        .strip_prefix("http://")
        .context("DNS proxy must use loopback HTTP")?;
    let value = value.strip_suffix('/').unwrap_or(value);
    let port = value
        .strip_prefix("127.0.0.1:")
        .or_else(|| value.strip_prefix("[::1]:"))
        .context("DNS proxy must be an explicit loopback HTTP URL without credentials")?;
    ensure!(
        !port.is_empty()
            && port.bytes().all(|c| c.is_ascii_digit())
            && port.parse::<u16>().unwrap_or(0) != 0,
        "Invalid loopback proxy port"
    );
    Ok(())
}

impl Config {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        ensure!(
            raw.len() as u64 <= MAX_JSON,
            "Configuration exceeds size limit"
        );
        let config: Self = serde_json::from_slice(raw).context("Invalid configuration JSON")?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.interfaces.is_empty() && self.interfaces.len() <= 32,
            "Provide 1 to 32 physical en interfaces"
        );
        for name in &self.interfaces {
            let suffix = name
                .strip_prefix("en")
                .context("Only explicit physical en interfaces are accepted")?;
            ensure!(
                !suffix.is_empty()
                    && suffix.len() <= 4
                    && suffix.bytes().all(|c| c.is_ascii_digit()),
                "Invalid physical interface"
            );
        }
        targets(&self.targets)?;
        if let Some(dns) = &self.dns {
            validate_hosts(&dns.hosts)?;
            validate_proxy(&dns.proxy)?;
            ensure!(
                (60..=86400).contains(&dns.refresh_seconds),
                "DNS interval must be 60..86400 seconds"
            );
        }
        let mut ids = BTreeSet::new();
        if let Some(modules) = &self.modules {
            ensure!(modules.len() <= 64, "At most 64 modules are allowed");
            let has_base =
                !self.targets.is_empty() || self.dns.as_ref().is_some_and(|d| !d.hosts.is_empty());
            ensure!(
                !has_base || modules.len() < 64,
                "Reserve one module slot to migrate base targets"
            );
            for module in modules {
                let id = &module.id;
                ensure!(
                    !id.is_empty()
                        && id.len() <= 64
                        && id.as_bytes()[0].is_ascii_alphanumeric()
                        && id.bytes().all(|c| c.is_ascii_lowercase()
                            || c.is_ascii_digit()
                            || b"_-".contains(&c))
                        && ids.insert(id),
                    "Module IDs must be unique lowercase identifiers"
                );
                ensure!(
                    !module.name.trim().is_empty()
                        && module.name.chars().count() <= 80
                        && !module.name.chars().any(char::is_control),
                    "Invalid visible module name"
                );
                targets(&module.targets)?;
                validate_hosts(&module.hosts)?;
                ensure!(
                    !module.targets.is_empty() || !module.hosts.is_empty(),
                    "A module needs targets or hostnames"
                );
            }
        }
        self.static_policy()?;
        let hosts = self.hosts();
        validate_hosts(&hosts)?;
        ensure!(
            hosts.is_empty() || self.dns.is_some(),
            "Hostname modules require DNS proxy settings"
        );
        Ok(())
    }

    pub fn hosts(&self) -> Vec<String> {
        self.dns
            .iter()
            .flat_map(|d| d.hosts.iter())
            .chain(
                self.modules
                    .iter()
                    .flatten()
                    .filter(|m| m.enabled)
                    .flat_map(|m| m.hosts.iter()),
            )
            .map(|s| s.to_ascii_lowercase())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn static_policy(&self) -> Result<Policy> {
        let mut merged = targets(&self.targets)?;
        for module in self.modules.iter().flatten().filter(|m| m.enabled) {
            merged.extend(targets(&module.targets)?);
        }
        ensure!(merged.len() <= 4096, "Combined target count exceeds limit");
        Ok(Policy {
            interfaces: self
                .interfaces
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            targets: merged,
        })
    }

    pub fn editable(&self) -> Self {
        let mut config = self.clone();
        let base_hosts = config
            .dns
            .as_ref()
            .map(|d| d.hosts.clone())
            .unwrap_or_default();
        let modules = config.modules.get_or_insert_with(Vec::new);
        if !config.targets.is_empty() || !base_hosts.is_empty() {
            let mut id = "existing-protection".to_string();
            let mut index = 1;
            while modules.iter().any(|m| m.id == id) {
                id = format!("existing-protection-{index}");
                index += 1;
            }
            modules.push(Module {
                id,
                name: "现有保护".into(),
                enabled: true,
                targets: std::mem::take(&mut config.targets),
                hosts: base_hosts,
            });
            if let Some(dns) = config.dns.as_mut() {
                dns.hosts.clear();
            }
        }
        config
    }
}

impl Policy {
    pub fn render(&self) -> String {
        let values = self
            .targets
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let mut text = format!("table <eg_targets> {{ {values} }}\n");
        for interface in &self.interfaces {
            for (family, label) in [("inet", "eg_v4"), ("inet6", "eg_v6")] {
                text.push_str(&format!("block drop out quick on {interface} {family} from any to <eg_targets> label \"{label}\"\n"));
            }
        }
        text
    }

    pub fn fingerprint(&self) -> String {
        digest(self.render().as_bytes())
    }
}

pub fn global_address(address: IpAddr) -> bool {
    let excluded: &[&str] = match address {
        IpAddr::V4(_) => &[
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/4",
            "240.0.0.0/4",
        ],
        IpAddr::V6(_) => {
            if !"2000::/3"
                .parse::<IpNet>()
                .expect("constant network")
                .contains(&address)
            {
                return false;
            }
            &["2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"]
        }
    };
    !excluded.iter().any(|s| {
        s.parse::<IpNet>()
            .expect("constant network")
            .contains(&address)
    })
}

pub fn valid_digest(value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|c| c.is_ascii_hexdigit()) {
        bail!("Expected a SHA-256 configuration version");
    }
    Ok(())
}
