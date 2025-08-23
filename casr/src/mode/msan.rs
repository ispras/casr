//! Stream module implements `Mode` trait for MemorySanitizer.
use std::{any::Any, process::Command};

use anyhow::{Result, bail};

use libcasr::{
    init_ignored_frames,
    msan::MsanCrash,
    report::CrashReport,
    stacktrace::{Filter, Stacktrace},
};

use super::{Mode, RunResult, SanMode};

/// Structure provides an interface for making all language depended actions.
#[derive(Clone, Debug, Default)]
pub struct MsanMode {
    san: SanMode,
}

impl MsanMode {
    pub fn new() -> Self {
        Default::default()
    }
}

impl Mode for MsanMode {
    fn pre_action(&self, _argv: &mut [String]) -> Result<()> {
        init_ignored_frames!("cpp");
        Ok(())
    }
    fn update_cmd(&self, cmd: &mut Command) -> Result<()> {
        self.san.update_cmd(cmd)
    }
    fn get_extractor(
        &self,
        _stdout: &str,
        stderr: &str,
        _signal: Option<i32>,
    ) -> Result<Option<RunResult>> {
        let Some(crash) = MsanCrash::new(stderr)? else {
            bail!("MemorySanitizer crash is not found!");
        };
        Ok(Some((Box::new(crash), Box::new(Self::new()))))
    }
    fn fill_report(&self, report: &mut CrashReport, raw_report: Vec<String>) {
        report.msan_report = raw_report;
    }
    fn check_exception(&self, report: &mut CrashReport, stream: &str) {
        self.san.check_exception(report, stream)
    }
    fn literal(&self) -> &str {
        "msan"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
