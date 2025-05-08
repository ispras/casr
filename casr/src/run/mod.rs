pub mod gdb;
pub mod stream;

use std::path::PathBuf;

use anyhow::Result;

use libcasr::report::{CrashReport, ReportExtractor};

use crate::mode::DynMode;

// TODO: Docs
pub trait Runner {
    fn run(
        &self,
        _mode: &mut DynMode,
        _argv: &[String],
        _stdin: &Option<PathBuf>,
        _timeout: u64,
        _ld_preload: &Option<String>,
    ) -> Result<Option<(CrashReport, Box<dyn ReportExtractor>)>>;
}
