use std::{
    any::Any,
    path::{Path, PathBuf},
};

use anyhow::{Result, bail};

use libcasr::{
    init_ignored_frames,
    lua::LuaException,
    report::CrashReport,
    stacktrace::{Filter, Stacktrace},
};

use crate::util;

use super::{Mode, RunResult};

// TODO: docs
#[derive(Clone, Debug, Default)]
pub struct LuaMode {}

impl LuaMode {
    pub fn new() -> Self {
        Default::default()
    }
}

impl Mode for LuaMode {
    fn pre_action(&self, _argv: &mut [String]) -> Result<()> {
        init_ignored_frames!("lua");
        Ok(())
    }
    fn get_extractor(
        &self,
        _stdout: &str,
        stderr: &str,
        _signal: Option<i32>,
    ) -> Result<Option<RunResult>> {
        let Some(exception) = LuaException::new(stderr) else {
            bail!("Lua exception is not found!");
        };
        Ok(Some((Box::new(exception), Box::new(Self::new()))))
    }
    fn get_report_stub(&self, argv: &[String], stdin: &Option<PathBuf>) -> Result<CrashReport> {
        let mut report = util::get_report_stub(argv, stdin);
        if argv.len() > 1
            && let Some(fname) = Path::new(&argv[0]).file_name()
        {
            let fname = fname.to_string_lossy();
            if fname.starts_with("lua") && !fname.ends_with(".lua") && argv[1].ends_with(".lua") {
                report.executable_path = argv[1].to_string();
            }
        }
        Ok(report)
    }
    fn fill_report(&self, report: &mut CrashReport, raw_report: Vec<String>) {
        report.lua_report = raw_report;
    }
    fn literal(&self) -> &str {
        "lua"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
