//! Stream module implements `Mode` trait for go.
use std::{any::Any, process::Command};

use anyhow::Result;

use libcasr::{
    go::GoPanic,
    init_ignored_frames,
    report::CrashReport,
    stacktrace::{Filter, Stacktrace},
};

use super::{Mode, RunResult, san::SanMode};

/// Structure provides an interface for making all language depended actions.
#[derive(Clone, Debug, Default)]
pub struct GoMode {
    san: SanMode,
}

impl GoMode {
    pub fn new() -> Self {
        Default::default()
    }
}

impl Mode for GoMode {
    fn pre_action(&self, _argv: &mut [String]) -> Result<()> {
        init_ignored_frames!("cpp", "go");
        Ok(())
    }
    fn update_cmd(&self, cmd: &mut Command) -> Result<()> {
        self.san.update_cmd(cmd)
    }
    fn get_extractor(
        &self,
        _stdout: &str,
        stderr: &str,
        signal: Option<i32>,
    ) -> Result<Option<RunResult>> {
        if let Some(panic) = GoPanic::new(stderr) {
            Ok(Some((Box::new(panic), Box::new(Self::new()))))
        } else {
            self.san.get_san_extractor(stderr, signal)
        }
    }
    fn fill_report(&self, report: &mut CrashReport, raw_report: Vec<String>) {
        report.go_report = raw_report;
    }
    fn check_exception(&self, report: &mut CrashReport, stream: &str) {
        self.san.check_exception(report, stream)
    }
    fn literal(&self) -> &str {
        "go"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
