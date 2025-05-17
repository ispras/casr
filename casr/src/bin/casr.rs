use casr::run;

use anyhow::Result;

use std::env;

fn main() -> Result<()> {
    run::casr(&env::args().collect::<Vec<String>>(), None)
}
