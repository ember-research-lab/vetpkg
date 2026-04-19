use crate::types::PolicyConfig;

pub mod audit;
pub mod audit_ci;

pub fn run(args: Vec<String>) -> Result<u8, String> {
    let mut it = args.into_iter();
    let _bin = it.next();
    let cmd = match it.next() {
        Some(c) => c,
        None => {
            print_help();
            return Ok(0);
        }
    };
    let rest: Vec<String> = it.collect();
    match cmd.as_str() {
        "daemon" => daemon(rest),
        "init" => init_cmd(),
        "status" => status(rest),
        "policy" => policy(),
        "audit" => audit::run(rest),
        "audit-ci" => audit_ci::run(rest),
        "--help" | "-h" | "help" => {
            print_help();
            Ok(0)
        }
        "--version" | "-V" => {
            println!("vetpkg {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        other => Err(format!("unknown subcommand: {other}")),
    }
}

fn print_help() {
    println!(
        "vetpkg {} — zero-dependency supply-chain security proxy

USAGE:
    vetpkg <COMMAND>

COMMANDS:
    daemon       Run the local proxy registry
    init         Write default config + pattern files
    status       Check daemon status
    policy       Print effective policy thresholds
    audit        Score a lockfile (Phase 1+)
    audit-ci     Audit GitHub Actions workflows (Phase 5+)
    help         Print this help
    --version    Print version

See: docs/plan/00-master-plan.md",
        env!("CARGO_PKG_VERSION")
    );
}

fn daemon(args: Vec<String>) -> Result<u8, String> {
    let mut cfg = PolicyConfig::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                i += 1;
                cfg.port = args
                    .get(i)
                    .ok_or("--port requires a value")?
                    .parse()
                    .map_err(|e| format!("--port: {e}"))?;
            }
            "--config" => {
                i += 1;
                let path = args.get(i).ok_or("--config requires a value")?;
                cfg = crate::store::load_config(std::path::Path::new(path))?;
            }
            other => return Err(format!("unknown daemon flag: {other}")),
        }
        i += 1;
    }
    crate::net::proxy::serve(cfg)
}

fn init_cmd() -> Result<u8, String> {
    let dir = crate::platform::config_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {:?}: {e}", dir))?;
    println!("wrote {}", dir.display());
    Ok(0)
}

fn status(_args: Vec<String>) -> Result<u8, String> {
    let cfg = PolicyConfig::default();
    match std::net::TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", cfg.port).parse().unwrap(),
        std::time::Duration::from_millis(500),
    ) {
        Ok(_) => {
            println!("vetpkg: running on 127.0.0.1:{}", cfg.port);
            Ok(0)
        }
        Err(_) => {
            println!("vetpkg: not running on 127.0.0.1:{}", cfg.port);
            Ok(1)
        }
    }
}

fn policy() -> Result<u8, String> {
    let cfg = PolicyConfig::default();
    println!("port                        {}", cfg.port);
    println!("allow threshold             < {:.2}", cfg.allow_threshold);
    println!("block threshold             >= {:.2}", cfg.block_threshold);
    println!(
        "typosquat distance          < {:.2}",
        cfg.typosquat_distance_threshold
    );
    println!(
        "fresh package hours         < {:.1}",
        cfg.fresh_package_hours
    );
    println!("upstream npm                {}", cfg.npm_upstream);
    println!("upstream pypi               {}", cfg.pypi_upstream);
    println!("upstream cargo index        {}", cfg.cargo_index_upstream);
    println!("upstream cargo download     {}", cfg.cargo_dl_upstream);
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_does_not_panic() {
        print_help();
    }

    #[test]
    fn policy_prints_ok() {
        assert_eq!(policy().unwrap(), 0);
    }

    #[test]
    fn unknown_subcommand_errors() {
        let r = run(vec!["vetpkg".into(), "no-such".into()]);
        assert!(r.is_err());
    }

    #[test]
    fn version_flag_works() {
        let r = run(vec!["vetpkg".into(), "--version".into()]);
        assert_eq!(r.unwrap(), 0);
    }
}
