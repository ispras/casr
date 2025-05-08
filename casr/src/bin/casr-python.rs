use anyhow::Result;

use ::casr::{
    casr,
    mode::{DynMode, python::PythonMode},
};

fn main() -> Result<()> {
    casr::stub(DynMode::new::<PythonMode>())
}
