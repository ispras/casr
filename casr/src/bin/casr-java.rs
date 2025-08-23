use anyhow::Result;

use ::casr::{
    casr,
    mode::{DynMode, java::JavaMode},
};

fn main() -> Result<()> {
    casr::stub(DynMode::new::<JavaMode>())
}
