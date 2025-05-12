use std::env;
use std::process::Command;

pub fn stub(subcommand: &str) {
    // Get all command-line arguments
    let args: Vec<String> = env::args().collect();
    let args = &args[1..];

    // Execute casr
    let result = Command::new("casr").arg(subcommand).args(args).status();

    // Handle execution result
    match result {
        Ok(status) => {
            std::process::exit(status.code().unwrap_or(1));
        }
        Err(e) => {
            eprintln!("Error executing casr: {}", e);
            std::process::exit(1);
        }
    }
}
