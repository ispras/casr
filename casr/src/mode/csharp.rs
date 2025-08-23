//! Stream module implements `Mode` trait for csharp.
use std::{any::Any, path::PathBuf, process::Command};

use anyhow::{Result, bail};

use libcasr::{
    csharp::CSharpException,
    init_ignored_frames,
    report::CrashReport,
    stacktrace::{Filter, Stacktrace},
};

use super::{Mode, RunResult, san::SanMode};

/// Structure provides an interface for making all language depended actions.
#[derive(Clone, Debug, Default)]
pub struct CSharpMode {
    san: SanMode,
}

impl CSharpMode {
    pub fn new() -> Self {
        Default::default()
    }
}

impl Mode for CSharpMode {
    fn pre_action(&self, argv: &mut [String]) -> Result<()> {
        // Check that args are valid.
        if !argv
            .iter()
            .any(|x| x.ends_with(".dll") || x.ends_with(".exe") || x.ends_with(".csproj"))
        {
            bail!("dotnet/mono target is not specified by .dll, .exe or .csproj executable.");
        };
        init_ignored_frames!("cpp", "csharp");
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
        if let Some(exception) = CSharpException::new(stderr)? {
            Ok(Some((Box::new(exception), Box::new(Self::new()))))
        } else {
            self.san.get_san_extractor(stderr, signal)
        }
    }
    fn get_report_stub(&self, argv: &[String], stdin: &Option<PathBuf>) -> Result<CrashReport> {
        let mut report = self.san.get_report_stub(argv, stdin)?;
        // Set executable path (for C# .dll, .csproj (dotnet) or .exe (mono) file).
        let pos = argv
            .iter()
            .position(|x| x.ends_with(".dll") || x.ends_with(".exe") || x.ends_with(".csproj"))
            .unwrap();
        report.executable_path = argv.get(pos).unwrap().to_string();
        Ok(report)
    }
    fn fill_report(&self, report: &mut CrashReport, raw_report: Vec<String>) {
        report.csharp_report = raw_report;
    }
    fn literal(&self) -> &str {
        "csharp"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
