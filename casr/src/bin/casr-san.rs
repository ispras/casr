use anyhow::Result;

use ::casr::{
    casr,
    mode::{DynMode, san::SanMode},
};

fn main() -> Result<()> {
    casr::stub(DynMode::new::<SanMode>())
}
