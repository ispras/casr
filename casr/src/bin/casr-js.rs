use anyhow::Result;

use ::casr::{
    casr,
    mode::{DynMode, js::JsMode},
};

fn main() -> Result<()> {
    casr::stub(DynMode::new::<JsMode>())
}
