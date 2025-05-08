use std::{
    any::Any,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::Result;

use libcasr::{
    init_ignored_frames,
    python::PythonException,
    report::CrashReport,
    stacktrace::{Filter, Stacktrace},
};

use super::{Mode, RunResult, san::SanMode};

// TODO: docs
#[derive(Clone, Debug, Default)]
pub struct PythonMode {
    san: SanMode,
}

impl PythonMode {
    pub fn new() -> Self {
        Default::default()
    }
}

impl Mode for PythonMode {
    fn pre_action(&self, _argv: &mut [String]) -> Result<()> {
        init_ignored_frames!("cpp", "python");
        Ok(())
    }
    fn update_cmd(&self, cmd: &mut Command) -> Result<()> {
        self.san.update_cmd(cmd)
    }
    fn get_extractor(
        &self,
        stdout: &str,
        stderr: &str,
        signal: Option<i32>,
    ) -> Result<Option<RunResult>> {
        if let Some(exception) = PythonException::new(stdout, stderr)? {
            Ok(Some((Box::new(exception), Box::new(Self::new()))))
        } else {
            self.san.get_san_extractor(stderr, signal)
        }
    }
    fn get_report_stub(&self, argv: &[String], stdin: &Option<PathBuf>) -> Result<CrashReport> {
        let mut report = self.san.get_report_stub(argv, stdin)?;
        if argv.len() > 1
            && let Some(fname) = Path::new(&argv[0]).file_name()
        {
            let fname = fname.to_string_lossy();
            if fname.starts_with("python") && !fname.ends_with(".py") && argv[1].ends_with(".py") {
                report.executable_path = argv[1].to_string();
            }
        }
        Ok(report)
    }
    fn fill_report(&self, report: &mut CrashReport, raw_report: Vec<String>) {
        report.python_report = raw_report;
    }
    fn literal(&self) -> &str {
        "python"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
