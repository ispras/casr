use casr::{mode::Mode, stub};

use anyhow::Result;

fn main() -> Result<()> {
    stub::stub(Mode::Csharp)
}
