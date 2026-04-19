use std::process::ExitCode;

fn main() -> ExitCode {
    match vetpkg::cli::run(std::env::args().collect()) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("vetpkg: {e}");
            ExitCode::from(2)
        }
    }
}
