use anyhow::Result;

use ::casr::{
    casr,
    mode::{DynMode, lua::LuaMode},
};

fn main() -> Result<()> {
    casr::stub(DynMode::new::<LuaMode>())
}
