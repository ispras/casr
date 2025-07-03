use std::any::Any;

use anyhow::{Result, bail};

use libcasr::{
    init_ignored_frames,
    report::CrashReport,
    stacktrace::{Filter, Stacktrace},
};

use crate::{
    run::{Runner, gdb::GdbRunner},
    util,
};

use super::{Mode, RunResult};

// TODO: docs
#[derive(Clone, Debug, Default)]
pub struct GdbMode {}

impl GdbMode {
    pub fn new() -> Self {
        Default::default()
    }
}

impl Mode for GdbMode {
    fn pre_action(&self, _argv: &mut [String]) -> Result<()> {
        init_ignored_frames!("cpp", "rust");
        Ok(())
    }
    fn get_runner(&self) -> Box<dyn Runner> {
        Box::new(GdbRunner {})
    }
    fn get_extractor(
        &self,
        _stdout: &str,
        _stderr: &str,
        _signal: Option<i32>,
    ) -> Result<Option<RunResult>> {
        bail!("Unsupported extractor!")
    }
    fn check_exception(&self, report: &mut CrashReport, stream: &str) {
        util::check_exception(report, stream)
    }
    fn literal(&self) -> &str {
        "gdb"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
