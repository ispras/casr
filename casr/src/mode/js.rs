use std::{
    any::Any,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Result, bail};

use libcasr::{
    init_ignored_frames,
    js::JsException,
    report::CrashReport,
    stacktrace::{Filter, Stacktrace},
};

use crate::util;

use super::{Mode, RunResult, san::SanMode};

// TODO: docs
#[derive(Clone, Debug, Default)]
pub struct JsMode {
    san: SanMode,
}

impl JsMode {
    pub fn new() -> Self {
        Default::default()
    }
}

impl Mode for JsMode {
    fn pre_action(&self, argv: &mut [String]) -> Result<()> {
        // Adjust argv with absolute path to interpreter/fuzzer
        if argv.len() > 1 {
            let fpath = Path::new(&argv[0]);
            if let Some(fname) = fpath.file_name() {
                let path_to_tool = if fname == fpath.as_os_str() {
                    let Ok(full_path_to_tool) = which::which(fname) else {
                        bail!("{} is not found in PATH", argv[0]);
                    };
                    full_path_to_tool
                } else {
                    fpath.to_path_buf()
                };
                if !path_to_tool.exists() {
                    bail!("Could not find the tool in the specified path {}", argv[0]);
                }
                // Some ref magic
                argv[0] = path_to_tool.to_str().unwrap().to_string();
            }
        }
        init_ignored_frames!("cpp", "js");
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
        if let Some(exception) = JsException::new(stderr)? {
            Ok(Some((Box::new(exception), Box::new(Self::new()))))
        } else {
            self.san.get_san_extractor(stderr, signal)
        }
    }
    fn get_report_stub(&self, argv: &[String], stdin: &Option<PathBuf>) -> Result<CrashReport> {
        let mut report = util::get_report_stub(argv, stdin);
        if argv.len() > 1 {
            let fpath = Path::new(&argv[0]);
            if let Some(fname) = fpath.file_name() {
                let fname = fname.to_string_lossy();
                if (fname == "node" || fname == "jsfuzz") && argv[1].ends_with(".js") {
                    report.executable_path = argv[1].to_string();
                } else if argv.len() > 2
                    && fname == "npx"
                    && argv[1] == "jazzer"
                    && argv[2].ends_with(".js")
                {
                    report.executable_path = argv[2].to_string();
                }
            }
        }
        Ok(report)
    }
    fn fill_report(&self, report: &mut CrashReport, raw_report: Vec<String>) {
        report.js_report = raw_report;
    }
    fn literal(&self) -> &str {
        "js"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
