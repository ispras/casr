use anyhow::Result;

use ::casr::{
    casr,
    mode::{DynMode, csharp::CSharpMode},
};

fn main() -> Result<()> {
    casr::stub(DynMode::new::<CSharpMode>())
}
