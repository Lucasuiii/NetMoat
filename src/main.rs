use anyhow::{bail, ensure, Context, Result};
use netmoat::{
    config::{Config, MAX_JSON},
    service::Backend,
    system::{read_limited, Paths, RealRunner},
};
use std::path::PathBuf;

fn option(args: &[String], name: &str) -> Result<PathBuf> {
    let i = args
        .iter()
        .position(|s| s == name)
        .with_context(|| format!("Missing {name}"))?;
    Ok(args
        .get(i + 1)
        .with_context(|| format!("Missing value for {name}"))?
        .into())
}
fn flags(args: &[String], expected: &[&str]) -> Result<()> {
    ensure!(
        args.len() == expected.len() * 2,
        "Unexpected or missing arguments"
    );
    for pair in args.chunks(2) {
        ensure!(expected.contains(&pair[0].as_str()), "Unknown option");
    }
    for name in expected {
        ensure!(
            args.iter().filter(|s| s.as_str() == *name).count() == 1,
            "Duplicate or missing option"
        );
    }
    Ok(())
}
fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--version"] {
        println!("NetMoat {} (Rust)", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.is_empty() || args == ["--help"] {
        println!("NetMoat: render|validate --config FILE\nservice install --config FILE\nservice configure --config FILE --expected-sha SHA256\nservice run|status|snapshot|start|stop|upgrade|uninstall");
        return Ok(());
    }
    if matches!(args[0].as_str(), "render" | "validate") {
        flags(&args[1..], &["--config"])?;
        let config = Config::parse(&read_limited(&option(&args, "--config")?, MAX_JSON)?)?;
        if args[0] == "render" {
            print!("{}", config.static_policy()?.render());
        } else {
            println!("Configuration valid");
        }
        return Ok(());
    }
    ensure!(args[0] == "service", "Unknown command; use --help");
    ensure!(
        cfg!(target_os = "macos") && unsafe { libc::geteuid() } == 0,
        "Service operations require macOS administrator privileges"
    );
    let action = args.get(1).context("Missing service action")?;
    let rest = &args[2..];
    let backend = Backend {
        paths: Paths::system(),
        runner: &RealRunner,
    };
    match action.as_str() {
        "install" => {
            flags(rest, &["--config"])?;
            backend.install(&option(rest, "--config")?)?;
        }
        "configure" => {
            flags(rest, &["--config", "--expected-sha"])?;
            let expected = option(rest, "--expected-sha")?;
            backend.configure(
                &option(rest, "--config")?,
                expected.to_str().context("Invalid version")?,
            )?;
        }
        "status" => {
            ensure!(rest.is_empty(), "Unexpected arguments");
            println!("{}", serde_json::to_string_pretty(&backend.status())?);
            return Ok(());
        }
        "snapshot" => {
            ensure!(rest.is_empty(), "Unexpected arguments");
            println!("{}", serde_json::to_string_pretty(&backend.snapshot()?)?);
            return Ok(());
        }
        "run" => {
            ensure!(rest.is_empty(), "Unexpected arguments");
            return backend.run();
        }
        "start" | "stop" | "upgrade" | "uninstall" => {
            ensure!(rest.is_empty(), "Unexpected arguments");
            match action.as_str() {
                "start" => backend.start()?,
                "stop" => backend.stop()?,
                "upgrade" => backend.upgrade()?,
                "uninstall" => backend.uninstall()?,
                _ => unreachable!(),
            }
        }
        _ => bail!("Unknown service action"),
    }
    println!("{}", serde_json::to_string_pretty(&backend.status())?);
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(2);
    }
}
