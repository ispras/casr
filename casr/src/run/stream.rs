//! Stream module implements `Runner` trait for program where all needed CASR report info can be
//! extracted from in standard streams.
use std::{os::unix::process::ExitStatusExt, path::PathBuf, process::Command};

use anyhow::Result;

use libcasr::report::{CrashReport, ReportExtractor};

use crate::{mode::DynMode, util};

use super::Runner;

/// Structure provides an interface for running program.
pub struct StreamRunner {}

impl Runner for StreamRunner {
    fn run(
        &self,
        mode: &mut DynMode,
        argv: &[String],
        stdin: &Option<PathBuf>,
        timeout: u64,
        ld_preload: &Option<String>,
    ) -> Result<Option<(CrashReport, Box<dyn ReportExtractor>)>> {
        // Run program.
        let mut cmd = Command::new(&argv[0]);
        // Set ld preload
        if let Some(ld_preload) = ld_preload {
            cmd.env("LD_PRELOAD", ld_preload);
        }
        if let Some(file) = stdin {
            cmd.stdin(std::fs::File::open(file)?);
        }
        if argv.len() > 1 {
            cmd.args(&argv[1..]);
        }
        // Update mode-dependent characteristics
        mode.update_cmd(&mut cmd)?;
        // Get output
        let result = util::get_output(&mut cmd, timeout, true)?;
        let stdout = String::from_utf8_lossy(&result.stdout);
        let stderr = String::from_utf8_lossy(&result.stderr);
        let signal = result.status.signal();

        // Create report
        let report = mode.get_report_stub(argv, stdin)?;
        // Get report extractor
        let Some(extractor) = mode.get_extractor(&stdout, &stderr, signal)? else {
            return Ok(None);
        };
        Ok(Some((report, extractor)))
    }
}
