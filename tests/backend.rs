use anyhow::{bail, Result};
use netmoat::{
    config::{self, Config},
    dns::{self, Cache, Record, Records},
    pf::{self},
    service::{self, Backend, State},
    system::{
        self, atomic_write, now, write_json, Output, Paths, RealRunner, Runner, ANCHOR, FORMAT,
        LABEL, LAUNCHCTL, PF,
    },
};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn config_value() -> Value {
    json!({"interfaces":["en0"], "targets":[], "modules":[{
        "id":"work-service", "name":"Work", "enabled":true, "targets":["192.0.2.0/24"], "hosts":[]}]})
}
fn parse(value: Value) -> Config {
    Config::parse(&serde_json::to_vec(&value).unwrap()).unwrap()
}
fn with_dns() -> Config {
    let mut value = config_value();
    value["modules"][0]["hosts"] = json!(["service.example.com"]);
    value["dns"] = json!({"hosts":[],"proxy":"http://127.0.0.1:8080","refresh_seconds":300});
    parse(value)
}
fn fixture() -> (tempfile::TempDir, Paths) {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths {
        home: dir.path().join("home"),
        run: dir.path().join("run"),
        plist: dir.path().join("job.plist"),
        launcher: dir.path().join("launcher"),
        public_status: dir.path().join("public.json"),
        owner: unsafe { libc::geteuid() },
    };
    paths.mkdir(&paths.home).unwrap();
    paths.mkdir(&paths.run).unwrap();
    write_json(
        &paths.home.join("installed.json"),
        &json!({"format":FORMAT}),
        true,
    )
    .unwrap();
    write_json(&paths.home.join("policy.json"), &config_value(), true).unwrap();
    (dir, paths)
}

#[derive(Default)]
struct FakeState {
    calls: Vec<(String, Vec<String>)>,
    enabled: bool,
    parent_missing: bool,
    rules: String,
    table: BTreeSet<ipnet::IpNet>,
    loaded: bool,
    dns_body: Option<String>,
    fail_dns_v6: bool,
    corrupt_table: bool,
    log: Option<std::path::PathBuf>,
    panic_on_pf: bool,
    auto_apply: Option<Paths>,
    fail_bootstrap_once: bool,
    retain_on_flush: bool,
}
#[derive(Default, Clone)]
struct FakeRunner(Arc<Mutex<FakeState>>);
impl FakeRunner {
    fn calls(&self) -> Vec<(String, Vec<String>)> {
        self.0.lock().unwrap().calls.clone()
    }
    fn mutations(&self) -> Vec<Vec<String>> {
        self.calls()
            .into_iter()
            .filter(|(p, a)| {
                p == PF && (a.iter().any(|s| s == "-f" || s == "-F" || s == "-X") || a == &["-E"])
            })
            .map(|(_, a)| a)
            .collect()
    }
}
impl Runner for FakeRunner {
    fn run(&self, program: &str, args: &[&str], _: Duration) -> Result<Output> {
        let mut state = self.0.lock().unwrap();
        state
            .calls
            .push((program.into(), args.iter().map(|s| s.to_string()).collect()));
        if let Some(path) = &state.log {
            use std::io::Write;
            writeln!(
                fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?,
                "{program} {args:?}"
            )?;
        }
        if state.panic_on_pf && program == PF {
            drop(state);
            panic!("Injected PF runner panic");
        }
        let mut code = 0;
        let text = if program == PF {
            if args == ["-sr"] {
                if state.parent_missing {
                    "".into()
                } else {
                    "anchor \"com.apple/*\" all\n".into()
                }
            } else if args == ["-s", "info"] {
                format!(
                    "Status: {} for 1 days\n",
                    if state.enabled { "Enabled" } else { "Disabled" }
                )
            } else if args == ["-E"] {
                state.enabled = true;
                "Token : 777\n".into()
            } else if args.first() == Some(&"-X") {
                "".into()
            } else if args.last() == Some(&"show") {
                if state.corrupt_table {
                    "198.51.100.0/24\n".into()
                } else {
                    state.table.iter().map(|s| format!("{s}\n")).collect()
                }
            } else if args.last() == Some(&"-vvsr") {
                "block label \"eg_v4\"\n Packets: 3 Bytes: 100\nblock label \"eg_v6\"\n Packets: 4 Bytes: 200\n".into()
            } else if args.contains(&"-f") {
                if !args.contains(&"-n") {
                    let rules = fs::read_to_string(args.last().unwrap())?;
                    let table = rules
                        .lines()
                        .next()
                        .unwrap()
                        .split_once('{')
                        .unwrap()
                        .1
                        .split_once('}')
                        .unwrap()
                        .0;
                    state.table = config::targets(
                        &table
                            .split(',')
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(str::to_string)
                            .collect::<Vec<_>>(),
                    )?;
                    state.rules = rules.lines().skip(1).map(|s| format!("{s}\n")).collect();
                }
                "".into()
            } else if args.contains(&"-F") {
                if !state.retain_on_flush {
                    if args.last() == Some(&"rules") {
                        state.rules.clear();
                    }
                    if args.last() == Some(&"Tables") {
                        state.table.clear();
                    }
                }
                "".into()
            } else if args.last() == Some(&"-sr") {
                state.rules.clone()
            } else if args.contains(&"Tables") {
                if state.table.is_empty() {
                    "".into()
                } else {
                    "eg_targets\n".into()
                }
            } else {
                bail!("Unexpected fake PF call: {args:?}");
            }
        } else if program == LAUNCHCTL {
            if args.first() == Some(&"print") {
                if !state.loaded {
                    code = 113;
                }
                "state = running\n".into()
            } else if args.first() == Some(&"print-disabled") {
                format!("\"{LABEL}\" => false\n")
            } else if args.first() == Some(&"bootstrap") {
                if state.fail_bootstrap_once {
                    state.fail_bootstrap_once = false;
                    code = 5;
                } else {
                    state.loaded = true;
                }
                "".into()
            } else if args.first() == Some(&"bootout") {
                state.loaded = false;
                "".into()
            } else if args.first() == Some(&"kickstart") {
                if let Some(paths) = state.auto_apply.clone() {
                    let raw = fs::read(paths.home.join("policy.json"))?;
                    let config = Config::parse(&raw)?;
                    let policy = config.static_policy()?;
                    state.enabled = true;
                    state.table = policy.targets.clone();
                    state.rules = policy
                        .render()
                        .lines()
                        .skip(1)
                        .map(|s| format!("{s}\n"))
                        .collect();
                    atomic_write(
                        &paths.run.join("rules.pf"),
                        policy.render().as_bytes(),
                        0o600,
                        true,
                    )?;
                    atomic_write(
                        &paths.run.join("canonical.txt"),
                        state.rules.as_bytes(),
                        0o600,
                        true,
                    )?;
                    atomic_write(&paths.run.join("enable.log"), b"Token : 777\n", 0o600, true)?;
                    write_json(
                        &paths.run.join("state.json"),
                        &State {
                            state: "rules_loaded".into(),
                            updated_at: now(),
                            config_sha256: config::digest(&raw),
                            policy_sha256: policy.fingerprint(),
                            target_count: policy.targets.len(),
                            backend: "rust".into(),
                            ..State::default()
                        },
                        false,
                    )?;
                }
                "".into()
            } else {
                "".into()
            }
        } else if program == "/usr/bin/curl" {
            if state.fail_dns_v6 && args.last().unwrap().ends_with("AAAA") {
                bail!("Injected proxy failure");
            }
            state.dns_body.clone().unwrap_or_else(|| {
                if args.last().unwrap().ends_with("AAAA") {
                    json!({"Status":0,"Answer":[{"type":28,"data":"2606:4700:4700::1111"}]})
                        .to_string()
                } else {
                    json!({"Status":0,"Answer":[{"type":1,"data":"8.8.8.8"}]}).to_string()
                }
            })
        } else {
            bail!("Unapproved fake command: {program}");
        };
        Ok(Output {
            code,
            stdout: text,
            stderr: String::new(),
        })
    }
}

#[test]
fn strict_configuration_rejects_ambiguous_types_and_injection() {
    let cases = [
        json!(null),
        json!([]),
        json!({"interfaces":["en0"],"targets":[],"surprise":true}),
        json!({"interfaces":["en0\npass all"],"targets":[]}),
        json!({"interfaces":["utun0"],"targets":[]}),
        json!({"interfaces":[],"targets":[]}),
        json!({"interfaces":["en0"],"targets":["::1%evil"]}),
        json!({"interfaces":["en0"],"targets":["0.0.0.0/0"]}),
        json!({"interfaces":["en0"],"targets":["::/0"]}),
        json!({"interfaces":["en0"],"targets":["192.0.2.1\npass all"]}),
    ];
    for case in cases {
        assert!(
            Config::parse(case.to_string().as_bytes()).is_err(),
            "{case}"
        );
    }
    for value in [json!(1), json!("yes"), json!(null)] {
        let mut config = config_value();
        config["modules"][0]["enabled"] = value;
        assert!(Config::parse(config.to_string().as_bytes()).is_err());
    }
    let mut value = config_value();
    value["modules"][0]["extra"] = json!(true);
    assert!(Config::parse(value.to_string().as_bytes()).is_err());
}
#[test]
fn normalization_and_module_union_preserve_shared_targets() {
    let mut value = config_value();
    value["modules"].as_array_mut().unwrap().push(json!({"id":"other", "name":"Other", "enabled":true,"targets":["192.0.2.4/24","2001:db8::1"],"hosts":[]}));
    value["modules"][0]["enabled"] = json!(false);
    let policy = parse(value).static_policy().unwrap();
    assert!(policy.targets.contains(&"192.0.2.0/24".parse().unwrap()));
    assert_eq!(policy.targets.len(), 2);
    assert!(policy.render().contains("inet6"));
    assert!(!policy.render().contains("utun"));
}

#[test]
fn aggregate_limit_counts_unique_targets_across_modules() {
    let mut value = config_value();
    value["modules"][0]["targets"] = json!(vec!["192.0.2.1"; 4096]);
    let mut other = value["modules"][0].clone();
    other["id"] = json!("other");
    value["modules"].as_array_mut().unwrap().push(other);
    assert_eq!(parse(value).static_policy().unwrap().targets.len(), 1);
}
#[test]
fn disabling_all_modules_produces_empty_table() {
    let mut value = config_value();
    value["modules"][0]["enabled"] = json!(false);
    let policy = parse(value).static_policy().unwrap();
    assert!(policy.targets.is_empty());
    assert!(policy.render().contains("{  }"));
}
#[test]
fn modules_and_dns_limits_are_enforced() {
    let mut value = config_value();
    let module = value["modules"][0].clone();
    value["modules"].as_array_mut().unwrap().push(module);
    assert!(Config::parse(value.to_string().as_bytes()).is_err());
    for name in ["", "\n", "x\u{0}"] {
        let mut c = config_value();
        c["modules"][0]["name"] = json!(name);
        assert!(Config::parse(c.to_string().as_bytes()).is_err());
    }
    for host in [
        "localhost",
        "*.example.com",
        "-bad.example.com",
        "example.com\npass all",
        "你好.example.com",
        "a..com",
    ] {
        assert!(config::validate_hosts(&[host.into()]).is_err());
    }
    for proxy in [
        "",
        "http://example.com:8080",
        "https://127.0.0.1:8080",
        "http://u:p@127.0.0.1:8080",
        "http://127.0.0.1:0",
        "http://127.0.0.1:8080/path",
    ] {
        assert!(config::validate_proxy(proxy).is_err(), "{proxy}");
    }
    assert!(config::validate_proxy("http://[::1]:8080/").is_ok());
    let mut value = config_value();
    value["modules"][0]["hosts"] = json!(["service.example.com"]);
    assert!(Config::parse(value.to_string().as_bytes()).is_err());
}
#[test]
fn mixed_and_legacy_configuration_migrate_without_hidden_targets() {
    let mut value = config_value();
    value["targets"] = json!(["198.51.100.0/24"]);
    value["modules"][0]["enabled"] = json!(false);
    value["dns"] =
        json!({"hosts":["base.example.com"],"proxy":"http://127.0.0.1:8080","refresh_seconds":300});
    let original = parse(value);
    let migrated = original.editable();
    migrated.validate().unwrap();
    assert!(migrated.targets.is_empty());
    assert!(migrated.dns.as_ref().unwrap().hosts.is_empty());
    assert_eq!(
        original.static_policy().unwrap(),
        migrated.static_policy().unwrap()
    );
    assert_eq!(original.hosts(), migrated.hosts());
    assert_eq!(
        migrated
            .modules
            .as_ref()
            .unwrap()
            .iter()
            .filter(|m| m.enabled)
            .count(),
        1
    );
    assert_eq!(migrated, migrated.editable());
    let old = parse(json!({"interfaces":["en0"],"targets":["192.0.2.0/24"]}));
    assert_eq!(
        old.static_policy().unwrap(),
        old.editable().static_policy().unwrap()
    );
}
#[test]
fn malformed_dns_shapes_never_panic() {
    for value in [
        json!(null),
        json!([]),
        json!({}),
        json!({"Status":"0"}),
        json!({"Status":0,"Answer":{}}),
        json!({"Status":0,"Answer":[null]}),
        json!({"Status":0,"Answer":[{}]}),
        json!({"Status":0,"Answer":[{"type":1,"data":null}]}),
    ] {
        assert!(
            dns::parse_reply(value.to_string().as_bytes(), false).is_err(),
            "{value}"
        );
    }
    assert!(dns::parse_reply(br#"{"Status":0,"Answer":null}"#, false)
        .unwrap()
        .is_empty());
    assert!(dns::parse_reply(br#"{"Status":0}"#, false)
        .unwrap()
        .is_empty());
}
#[test]
fn unsafe_dns_addresses_and_family_mismatch_are_rejected() {
    for ip in [
        "127.0.0.1",
        "192.168.1.1",
        "198.18.0.1",
        "100.64.0.1",
        "192.0.2.1",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "::ffff:8.8.8.8",
    ] {
        assert!(!config::global_address(ip.parse().unwrap()), "{ip}");
    }
    for (kind, ip, v6) in [
        (1, "127.0.0.1", false),
        (1, "2606:4700::1111", false),
        (28, "8.8.8.8", true),
    ] {
        assert!(dns::parse_reply(
            json!({"Status":0,"Answer":[{"type":kind,"data":ip}]})
                .to_string()
                .as_bytes(),
            v6
        )
        .is_err());
    }
}
#[test]
fn dns_failure_retains_last_good_records_and_pf_rules() {
    let (_dir, paths) = fixture();
    let runner = FakeRunner::default();
    write_json(&paths.home.join("policy.json"), &with_dns(), true).unwrap();
    let backend = Backend {
        paths: paths.clone(),
        runner: &runner,
    };
    let mut cache = Cache::new(&paths);
    backend.tick(&mut cache).unwrap();
    let previous_rules = runner.0.lock().unwrap().rules.clone();
    runner.0.lock().unwrap().dns_body = Some(json!({"Status":0,"Answer":null}).to_string());
    let mut cache = Cache::new(&paths);
    let state = backend.tick(&mut cache).unwrap();
    assert_eq!(state.state, "rules_loaded");
    assert_eq!(runner.0.lock().unwrap().rules, previous_rules);
    assert!(!runner
        .mutations()
        .iter()
        .any(|args| args.contains(&"-F".into()) || args.contains(&"-X".into())));
    assert_eq!(cache.records["service.example.com"].addresses.len(), 2);
}
#[test]
fn missing_or_corrupt_dns_cache_never_replaces_existing_rules_with_partial_policy() {
    let (_dir, paths) = fixture();
    let runner = FakeRunner::default();
    let backend = Backend {
        paths: paths.clone(),
        runner: &runner,
    };
    backend.tick(&mut Cache::new(&paths)).unwrap();
    let before = runner.0.lock().unwrap().rules.clone();
    let mutations = runner.mutations().len();
    write_json(&paths.home.join("policy.json"), &with_dns(), true).unwrap();
    for bad_cache in [
        json!([]),
        json!(null),
        json!({"service.example.com":{"addresses":null,"resolved_at":1}}),
    ] {
        write_json(&paths.home.join("dns-cache.json"), &bad_cache, true).unwrap();
        runner.0.lock().unwrap().dns_body = Some("[]".into());
        assert!(backend.tick(&mut Cache::new(&paths)).is_err());
        assert_eq!(runner.0.lock().unwrap().rules, before);
        assert_eq!(runner.mutations().len(), mutations);
    }
}
#[test]
fn partial_address_family_failure_keeps_previous_host_record() {
    let (_dir, paths) = fixture();
    let runner = FakeRunner::default();
    let config = with_dns();
    let old = Record {
        addresses: vec!["1.1.1.1".into()],
        resolved_at: now() - 2000.0,
    };
    write_json(
        &paths.home.join("dns-cache.json"),
        &Records::from([("service.example.com".into(), old)]),
        true,
    )
    .unwrap();
    runner.0.lock().unwrap().fail_dns_v6 = true;
    let mut cache = Cache::new(&paths);
    cache.refresh(&config, &paths, &runner).unwrap();
    assert_eq!(cache.records["service.example.com"].addresses, ["1.1.1.1"]);
    let (_, state) = dns::effective(&config, &cache.records, now()).unwrap();
    assert_eq!(state.stale_hosts, ["service.example.com"]);
}
#[test]
fn renaming_module_does_not_repeat_dns_queries() {
    let (_dir, paths) = fixture();
    let runner = FakeRunner::default();
    let mut config = with_dns();
    let mut cache = Cache::new(&paths);
    cache.refresh(&config, &paths, &runner).unwrap();
    let count = runner.calls().len();
    config.modules.as_mut().unwrap()[0].name = "Renamed".into();
    cache.refresh(&config, &paths, &runner).unwrap();
    assert_eq!(count, runner.calls().len());
    for (program, args) in runner.calls() {
        if program == "/usr/bin/curl" {
            assert!(args
                .windows(2)
                .any(|a| a == ["--proxy", "http://127.0.0.1:8080"]));
            assert!(args.windows(2).any(|a| a == ["--noproxy", ""]));
        }
    }
}
#[test]
fn disabled_hostname_module_never_queries_dns() {
    let (_dir, paths) = fixture();
    let runner = FakeRunner::default();
    let mut config = with_dns();
    config.modules.as_mut().unwrap()[0].enabled = false;
    let mut cache = Cache::new(&paths);
    cache.refresh(&config, &paths, &runner).unwrap();
    assert!(runner.calls().is_empty());
    assert!(dns::effective(&config, &cache.records, now())
        .unwrap()
        .0
        .targets
        .is_empty());
}
#[test]
fn rule_repair_reuses_token_without_global_mutations() {
    let (_dir, paths) = fixture();
    let runner = FakeRunner::default();
    let backend = Backend {
        paths: paths.clone(),
        runner: &runner,
    };
    let mut cache = Cache::new(&paths);
    backend.tick(&mut cache).unwrap();
    runner.0.lock().unwrap().rules.clear();
    backend.tick(&mut cache).unwrap();
    assert_eq!(
        runner
            .calls()
            .iter()
            .filter(|(p, a)| p == PF && a == &["-E"])
            .count(),
        1
    );
    for args in runner.mutations() {
        assert!(!args.contains(&"-d".into()));
        if args.contains(&"-f".into()) || args.contains(&"-F".into()) {
            assert!(args.windows(2).any(|a| a == ["-a", ANCHOR]));
        }
    }
}
#[test]
fn missing_parent_refuses_mutations_and_status_fails_closed() {
    let (_dir, paths) = fixture();
    let runner = FakeRunner::default();
    let backend = Backend {
        paths: paths.clone(),
        runner: &runner,
    };
    let state = backend.tick(&mut Cache::new(&paths)).unwrap();
    write_json(&paths.run.join("state.json"), &state, false).unwrap();
    {
        let mut r = runner.0.lock().unwrap();
        r.loaded = true;
        r.parent_missing = true;
    }
    let count = runner.mutations().len();
    assert!(backend.tick(&mut Cache::new(&paths)).is_err());
    assert_eq!(count, runner.mutations().len());
    assert!(!backend.status().rules_verified);
}
#[test]
fn invalid_reference_log_is_not_replaced_or_accumulated() {
    let (_dir, paths) = fixture();
    let runner = FakeRunner::default();
    atomic_write(&paths.run.join("enable.log"), b"not a token", 0o600, true).unwrap();
    let backend = Backend {
        paths: paths.clone(),
        runner: &runner,
    };
    assert!(backend.tick(&mut Cache::new(&paths)).is_err());
    assert!(runner.mutations().is_empty());
}
#[test]
fn parser_requires_complete_token_and_real_counters() {
    assert_eq!(pf::parse_token("Token : 777\n").unwrap(), "777");
    for value in ["Token: 1evil", "Token: 1\nToken: 2", "Token: x", ""] {
        assert!(pf::parse_token(value).is_err());
    }
    assert!(pf::counters("block label \"eg_v4\"\n").is_err());
    assert!(!pf::parent_loaded("anchor \"com.apple/other\" all"));
}
#[test]
fn cleanup_is_explicit_and_releases_only_owned_reference() {
    let (_dir, paths) = fixture();
    let runner = FakeRunner::default();
    let backend = Backend {
        paths: paths.clone(),
        runner: &runner,
    };
    backend.tick(&mut Cache::new(&paths)).unwrap();
    {
        let _guard = backend.guard();
    }
    assert!(!runner.mutations().iter().any(|a| a.contains(&"-F".into())));
    backend.guard().cleanup().unwrap();
    assert!(runner.calls().iter().any(|(_, a)| a == &["-X", "777"]));
    assert!(!paths.run.join("enable.log").exists());
}
#[test]
fn target_readback_failure_does_not_report_success() {
    let (_dir, paths) = fixture();
    let runner = FakeRunner::default();
    runner.0.lock().unwrap().corrupt_table = true;
    let backend = Backend {
        paths,
        runner: &runner,
    };
    assert!(backend.tick(&mut Cache::new(&backend.paths)).is_err());
    assert!(!runner.mutations().iter().any(|a| a.contains(&"-X".into())));
}
#[test]
fn failed_cleanup_retains_reference_and_recovery_files() {
    let (_dir, paths) = fixture();
    let runner = FakeRunner::default();
    let backend = Backend {
        paths: paths.clone(),
        runner: &runner,
    };
    backend.tick(&mut Cache::new(&paths)).unwrap();
    runner.0.lock().unwrap().retain_on_flush = true;
    assert!(backend.guard().cleanup().is_err());
    assert!(paths.run.join("enable.log").exists());
    assert!(!runner
        .calls()
        .iter()
        .any(|(_, a)| a.first() == Some(&"-X".to_string())));
}
#[test]
fn stale_gui_save_is_rejected_without_writing_or_commands() {
    let (dir, paths) = fixture();
    let runner = FakeRunner::default();
    let backend = Backend {
        paths: paths.clone(),
        runner: &runner,
    };
    let policy = paths.home.join("policy.json");
    let old = fs::read(&policy).unwrap();
    let candidate = dir.path().join("candidate.json");
    fs::write(&candidate, config_value().to_string()).unwrap();
    let error = backend
        .configure(&candidate, &"f".repeat(64))
        .unwrap_err()
        .to_string();
    assert!(error.contains("conflict"));
    assert_eq!(fs::read(policy).unwrap(), old);
    assert!(runner.calls().is_empty());
}
#[test]
fn rollback_cannot_erase_newer_successful_configuration() {
    let (_dir, paths) = fixture();
    let runner = FakeRunner::default();
    let backend = Backend {
        paths: paths.clone(),
        runner: &runner,
    };
    let path = paths.home.join("policy.json");
    let old = fs::read(&path).unwrap();
    let a = parse(json!({"interfaces":["en0"],"targets":["198.51.100.0/24"]}));
    write_json(&path, &a, true).unwrap();
    let sha = config::digest(&fs::read(&path).unwrap());
    let b = parse(json!({"interfaces":["en0"],"targets":["203.0.113.0/24"]}));
    write_json(&path, &b, true).unwrap();
    let newer = fs::read(&path).unwrap();
    assert!(!backend.rollback_if_current(&sha, &old).unwrap());
    assert_eq!(newer, fs::read(&path).unwrap());
}
#[test]
fn paused_service_configure_is_atomic_and_keeps_backup() {
    let (dir, paths) = fixture();
    let runner = FakeRunner::default();
    let backend = Backend {
        paths: paths.clone(),
        runner: &runner,
    };
    let path = paths.home.join("policy.json");
    let old = fs::read(&path).unwrap();
    let version = config::digest(&old);
    let candidate = dir.path().join("candidate.json");
    let mut value = config_value();
    value["modules"][0]["enabled"] = json!(false);
    fs::write(&candidate, value.to_string()).unwrap();
    backend.configure(&candidate, &version).unwrap();
    assert_eq!(
        fs::read(paths.home.join("policy.previous.json")).unwrap(),
        old
    );
    assert!(
        !Config::parse(&fs::read(path).unwrap())
            .unwrap()
            .modules
            .unwrap()[0]
            .enabled
    );
}
#[test]
fn live_configure_waits_for_daemon_acknowledgement() {
    let (dir, paths) = fixture();
    let runner = FakeRunner::default();
    runner.0.lock().unwrap().loaded = true;
    let backend = Backend {
        paths: paths.clone(),
        runner: &runner,
    };
    let state = backend.tick(&mut Cache::new(&paths)).unwrap();
    write_json(&paths.run.join("state.json"), &state, false).unwrap();
    let original = fs::read(paths.home.join("policy.json")).unwrap();
    let version = config::digest(&original);
    let candidate = dir.path().join("candidate.json");
    let mut value = config_value();
    value["modules"][0]["targets"] = json!(["198.51.100.0/24"]);
    fs::write(&candidate, value.to_string()).unwrap();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let deadline = Instant::now() + Duration::from_secs(3);
            while fs::read(paths.home.join("policy.json")).unwrap() == original {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(5));
            }
            let state = backend.tick(&mut Cache::new(&paths)).unwrap();
            write_json(&paths.run.join("state.json"), &state, false).unwrap();
        });
        backend.configure(&candidate, &version).unwrap();
    });
    assert!(backend.status().rules_verified);
}

fn legacy_files(paths: &Paths) -> (Vec<u8>, Vec<u8>) {
    let plist = format!("<plist>{LABEL} /usr/bin/python3 netmoat.py</plist>").into_bytes();
    let launcher = format!(
        "#!/bin/sh\nexec /usr/bin/python3 '{}/netmoat.py'\n",
        paths.home.display()
    )
    .into_bytes();
    atomic_write(&paths.plist, &plist, 0o644, true).unwrap();
    atomic_write(&paths.launcher, &launcher, 0o755, true).unwrap();
    atomic_write(
        &paths.home.join("netmoat.py"),
        b"# old backend",
        0o600,
        true,
    )
    .unwrap();
    atomic_write(
        &paths.home.join("netmoat_service.py"),
        b"# old service",
        0o600,
        true,
    )
    .unwrap();
    write_json(
        &paths.home.join("installed.json"),
        &json!({"format":"netmoat-service-v1"}),
        true,
    )
    .unwrap();
    (plist, launcher)
}
#[test]
fn successful_upgrade_preserves_policy_and_removes_old_installed_backend() {
    let (_dir, paths) = fixture();
    legacy_files(&paths);
    for name in ["netmoat.py.previous", "netmoat_service.py.previous"] {
        atomic_write(&paths.home.join(name), b"# old backup", 0o600, true).unwrap();
    }
    let original = fs::read(paths.home.join("policy.json")).unwrap();
    let runner = FakeRunner::default();
    {
        let mut r = runner.0.lock().unwrap();
        r.loaded = true;
        r.auto_apply = Some(paths.clone());
    }
    let backend = Backend {
        paths: paths.clone(),
        runner: &runner,
    };
    backend.upgrade().unwrap();
    assert!(backend.status().rules_verified);
    assert_eq!(fs::read(paths.home.join("policy.json")).unwrap(), original);
    assert!(
        !paths.home.join("netmoat.py").exists() && !paths.home.join("netmoat_service.py").exists()
    );
    assert!(!paths.home.join("upgrade-backup").exists());
    assert!(!paths.home.join("netmoat.py.previous").exists());
    assert!(!paths.home.join("netmoat_service.py.previous").exists());
    assert!(!fs::read_to_string(&paths.plist).unwrap().contains("python"));
    assert!(!fs::read_to_string(&paths.launcher)
        .unwrap()
        .contains("python"));
    assert!(paths.home.join("netmoat").exists());
}
#[test]
fn failed_upgrade_restores_previous_launch_configuration_and_keeps_backup() {
    let (_dir, paths) = fixture();
    let (plist, launcher) = legacy_files(&paths);
    let runner = FakeRunner::default();
    {
        let mut r = runner.0.lock().unwrap();
        r.loaded = true;
        r.fail_bootstrap_once = true;
    }
    let backend = Backend {
        paths: paths.clone(),
        runner: &runner,
    };
    assert!(backend.upgrade().is_err());
    assert_eq!(fs::read(&paths.plist).unwrap(), plist);
    assert_eq!(fs::read(&paths.launcher).unwrap(), launcher);
    assert!(paths.home.join("netmoat.py").exists() && paths.home.join("upgrade-backup").exists());
    assert!(runner.0.lock().unwrap().loaded);
}
#[test]
fn uninstall_cleans_only_framework_paths_after_explicit_rule_cleanup() {
    let (_dir, paths) = fixture();
    let runner = FakeRunner::default();
    runner.0.lock().unwrap().loaded = true;
    let backend = Backend {
        paths: paths.clone(),
        runner: &runner,
    };
    backend.tick(&mut Cache::new(&paths)).unwrap();
    atomic_write(
        &paths.plist,
        system::job_plist(&paths.home.join("netmoat"), &paths.home).as_bytes(),
        0o644,
        true,
    )
    .unwrap();
    atomic_write(
        &paths.launcher,
        format!("exec '{}/netmoat'\n", paths.home.display()).as_bytes(),
        0o755,
        true,
    )
    .unwrap();
    backend.uninstall().unwrap();
    assert!(
        !paths.home.exists()
            && !paths.run.exists()
            && !paths.launcher.exists()
            && !paths.plist.exists()
    );
    assert!(runner.calls().iter().any(|(_, a)| a == &["-X", "777"]));
}
#[test]
fn concurrent_management_is_refused_but_daemon_lock_is_independent() {
    let (_dir, paths) = fixture();
    let management = paths.lock(true, Duration::ZERO).unwrap();
    assert!(paths.lock(true, Duration::ZERO).is_err());
    let daemon = paths.lock(false, Duration::ZERO).unwrap();
    assert!(paths.lock(false, Duration::ZERO).is_err());
    drop(management);
    drop(daemon);
    assert!(paths.lock(true, Duration::ZERO).is_ok());
}

#[test]
fn snapshot_cannot_pair_configuration_with_another_transaction() {
    let (_dir, paths) = fixture();
    let runner = FakeRunner::default();
    let backend = Backend {
        paths: paths.clone(),
        runner: &runner,
    };
    let management = paths.lock(true, Duration::ZERO).unwrap();
    assert!(backend.snapshot().is_err());
    assert!(runner.calls().is_empty());
    drop(management);
    let result = backend.snapshot().unwrap();
    assert_eq!(
        result.configuration_sha256,
        config::digest(&fs::read(paths.home.join("policy.json")).unwrap())
    );
}
#[test]
fn root_paths_reject_symlinks_and_writable_files() {
    let (dir, paths) = fixture();
    let file = dir.path().join("file");
    fs::write(&file, "x").unwrap();
    let link = dir.path().join("link");
    symlink(&file, &link).unwrap();
    assert!(paths.secure(&link, false).is_err());
    assert!(system::read_limited(&link, 100).is_err());
    fs::set_permissions(&file, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(paths.secure(&file, false).is_err());
    assert!(system::read_limited(&file, 0).is_err());
}
#[test]
fn atomic_write_is_durable_and_private() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("state");
    atomic_write(&file, b"one", 0o600, true).unwrap();
    atomic_write(&file, b"two", 0o600, true).unwrap();
    assert_eq!(fs::read(&file).unwrap(), b"two");
    assert_eq!(fs::metadata(file).unwrap().mode() & 0o777, 0o600);
}
#[test]
fn status_has_no_network_requests_and_rejects_stale_heartbeat() {
    let (_dir, paths) = fixture();
    let runner = FakeRunner::default();
    let backend = Backend {
        paths: paths.clone(),
        runner: &runner,
    };
    let mut state = backend.tick(&mut Cache::new(&paths)).unwrap();
    runner.0.lock().unwrap().loaded = true;
    write_json(&paths.run.join("state.json"), &state, false).unwrap();
    assert!(backend.status().rules_verified);
    state.updated_at = now() - 1000.0;
    write_json(&paths.run.join("state.json"), &state, false).unwrap();
    assert!(!backend.status().rules_verified);
    assert!(!runner.calls().iter().any(|(p, _)| p == "/usr/bin/curl"));
}
#[test]
fn public_heartbeat_contains_no_private_configuration() {
    let (_dir, paths) = fixture();
    let state = State {
        state: "rules_loaded".into(),
        updated_at: now(),
        interfaces: vec!["en0".into()],
        error: Some("PRIVATE ERROR".into()),
        dns: Some(dns::DnsState {
            enabled: true,
            stale_hosts: vec!["private.example.com".into()],
        }),
        ..State::default()
    };
    service::publish(&paths, &state).unwrap();
    let public = fs::read_to_string(&paths.public_status).unwrap();
    assert!(
        !public.contains("private.example.com")
            && !public.contains("PRIVATE ERROR")
            && !public.contains("en0")
    );
    assert_eq!(
        fs::metadata(paths.public_status).unwrap().mode() & 0o777,
        0o644
    );
}
#[test]
fn real_runner_enforces_timeout_and_output_limit() {
    let start = Instant::now();
    assert!(RealRunner
        .run("/bin/sleep", &["5"], Duration::from_millis(80))
        .is_err());
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(RealRunner
        .run(
            "/usr/bin/head",
            &["-c", "2000000", "/dev/zero"],
            Duration::from_secs(3)
        )
        .is_err());
    assert_eq!(
        RealRunner
            .run("/bin/echo", &["ok"], Duration::from_secs(2))
            .unwrap()
            .stdout,
        "ok\n"
    );
}
#[test]
fn real_runner_handles_inherited_blocked_sigchld() {
    use std::os::unix::process::CommandExt;
    use wait_timeout::ChildExt;
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", "real_runner_enforces_timeout_and_output_limit"]);
    // Administrator authorization can pass a blocked SIGCHLD mask to the CLI.
    // Change only the fixture child, never the parallel test process.
    unsafe {
        command.pre_exec(|| {
            let mut signals: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut signals);
            libc::sigaddset(&mut signals, libc::SIGCHLD);
            let result = libc::pthread_sigmask(libc::SIG_BLOCK, &signals, std::ptr::null_mut());
            if result == 0 {
                Ok(())
            } else {
                Err(std::io::Error::from_raw_os_error(result))
            }
        });
    }
    let mut child = command.spawn().unwrap();
    let status = child.wait_timeout(Duration::from_secs(8)).unwrap();
    if status.is_none() {
        child.kill().unwrap();
        child.wait().unwrap();
    }
    assert!(
        status.is_some_and(|s| s.success()),
        "Blocked-signal fixture failed"
    );
}
#[test]
fn deterministic_malformed_input_sweep_does_not_panic() {
    let mut seed = 1234567u64;
    for length in 0..500 {
        let bytes = (0..length % 128)
            .map(|_| {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                (seed >> 32) as u8
            })
            .collect::<Vec<_>>();
        let _ = Config::parse(&bytes);
        let _ = dns::parse_reply(&bytes, false);
    }
}

#[test]
#[ignore]
fn service_process_fixture() {
    let root = std::env::var_os("NETMOAT_TEST_FIXTURE").expect("Only run through fixture parent");
    let root = Path::new(&root);
    let paths: Paths = Paths {
        home: root.join("home"),
        run: root.join("run"),
        plist: root.join("job.plist"),
        launcher: root.join("launcher"),
        public_status: root.join("public.json"),
        owner: unsafe { libc::geteuid() },
    };
    let runner = FakeRunner::default();
    {
        let mut r = runner.0.lock().unwrap();
        r.log = Some(root.join("calls.log"));
        r.panic_on_pf = std::env::var_os("NETMOAT_TEST_PANIC").is_some();
    }
    let backend = Backend {
        paths,
        runner: &runner,
    };
    backend.run().unwrap();
}
#[test]
fn sigterm_retains_rules_and_next_process_adopts_reference() {
    use wait_timeout::ChildExt;
    let (dir, paths) = fixture();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "service_process_fixture",
            "--ignored",
            "--nocapture",
        ])
        .env("NETMOAT_TEST_FIXTURE", dir.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !paths.run.join("state.json").exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(paths.run.join("state.json").exists());
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let exit = child.wait_timeout(Duration::from_secs(3)).unwrap();
    if exit.is_none() {
        child.kill().unwrap();
        child.wait().unwrap();
        panic!("SIGTERM did not finish promptly");
    }
    assert!(exit.unwrap().success());
    let calls = fs::read_to_string(dir.path().join("calls.log")).unwrap();
    assert!(!calls.contains("\"-F\"") && !calls.contains("\"-X\""));
    assert_eq!(
        pf::parse_token(&fs::read_to_string(paths.run.join("enable.log")).unwrap()).unwrap(),
        "777"
    );
    let runner = FakeRunner::default();
    runner.0.lock().unwrap().enabled = true;
    let backend = Backend {
        paths,
        runner: &runner,
    };
    backend.tick(&mut Cache::new(&backend.paths)).unwrap();
    assert!(!runner.calls().iter().any(|(_, a)| a == &["-E"]));
}
#[test]
fn unexpected_panic_does_not_clean_existing_rules_or_token() {
    let (dir, paths) = fixture();
    atomic_write(&paths.run.join("enable.log"), b"Token : 777\n", 0o600, true).unwrap();
    let exit = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "service_process_fixture", "--ignored"])
        .env("NETMOAT_TEST_FIXTURE", dir.path())
        .env("NETMOAT_TEST_PANIC", "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(!exit.success());
    assert!(paths.run.join("enable.log").exists());
    let calls = fs::read_to_string(dir.path().join("calls.log")).unwrap();
    assert!(!calls.contains("\"-F\"") && !calls.contains("\"-X\""));
}
