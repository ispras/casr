use std::{any::Any, process::Command};

use anyhow::{Result, bail};

use libcasr::{
    asan::AsanCrash,
    init_ignored_frames,
    report::CrashReport,
    stacktrace::{Filter, Stacktrace},
};

use super::{Mode, RunResult, SanMode};

// TODO: docs
#[derive(Clone, Debug, Default)]
pub struct AsanMode {
    san: SanMode,
}

impl AsanMode {
    pub fn new() -> Self {
        Default::default()
    }
}

impl Mode for AsanMode {
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
        let Some(crash) = AsanCrash::new(stderr)? else {
            bail!("AddressSanitizer crash is not found!");
        };
        Ok(Some((Box::new(crash), Box::new(Self::new()))))
    }
    fn fill_report(&self, report: &mut CrashReport, raw_report: Vec<String>) {
        report.asan_report = raw_report;
    }
    fn check_exception(&self, report: &mut CrashReport, stream: &str) {
        self.san.check_exception(report, stream)
    }
    fn literal(&self) -> &str {
        "asan"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
