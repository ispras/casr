use crate::{mode::Mode, run};

use std::env;

use anyhow::Result;

pub fn stub(mode: Mode) -> Result<()> {
    let subcommand = mode.to_string();
    let mut args: Vec<String> = env::args().collect();
    args.insert(1, subcommand);
    run::casr(&args, Some(mode))
}
