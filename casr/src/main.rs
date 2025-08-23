use std::env;

use anyhow::Result;

use casr::casr;

fn main() -> Result<()> {
    casr::casr(&env::args().collect::<Vec<String>>(), None)
}
