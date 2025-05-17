use std::env;
use std::ffi::CString;
use std::str::FromStr;

use anyhow::{Result, bail};
use nix::unistd;

pub fn stub(subcommand: &str) -> Result<()> {
    // Get all command-line arguments
    let args: Vec<String> = env::args().collect();
    let args = &args[1..];

    // Get casr path
    let casr = env::current_exe()
        .unwrap()
        .as_path()
        .parent()
        .unwrap()
        .join("casr")
        .to_str()
        .unwrap()
        .to_string();
    let casr = CString::new(casr).unwrap();

    // Collect argv
    let mut argv = vec![casr.clone()];
    argv.push(CString::from_str(subcommand).unwrap());
    argv.extend(args.iter().map(|arg| CString::from_str(arg).unwrap()));

    // Execute casr
    let Err(err) = unistd::execv(&casr, &argv);
    bail!("Failed to execute {}: {}", casr.to_str().unwrap(), err);
}
