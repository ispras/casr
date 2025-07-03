use anyhow::Result;

use ::casr::{
    casr,
    mode::{DynMode, gdb::GdbMode},
};

fn main() -> Result<()> {
    casr::stub(DynMode::new::<GdbMode>())
}
