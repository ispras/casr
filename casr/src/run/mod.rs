//! Provides API's for running program.
pub mod gdb;
pub mod stream;

use std::path::PathBuf;

use anyhow::Result;

use libcasr::report::{CrashReport, ReportExtractor};

use crate::mode::DynMode;

/// Run program
pub trait Runner {
    /// Run target program and extract base CASR report info
    fn run(
        &self,
        _mode: &mut DynMode,
        _argv: &[String],
        _stdin: &Option<PathBuf>,
        _timeout: u64,
        _ld_preload: &Option<String>,
    ) -> Result<Option<(CrashReport, Box<dyn ReportExtractor>)>>;
}
