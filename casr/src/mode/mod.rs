//! Provides API's for running target program and parsing output.
pub mod asan;
pub mod csharp;
pub mod gdb;
pub mod go;
pub mod java;
pub mod js;
pub mod lua;
pub mod msan;
pub mod python;
pub mod rust;
pub mod san;

use std::{
    any::Any,
    fmt,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Result, bail};
use clap::ArgMatches;

use libcasr::{
    report::{CrashReport, ReportExtractor},
    stacktrace::DebugInfo,
};

use crate::{
    run::{Runner, gdb::GdbRunner, stream::StreamRunner},
    util,
};

use self::{
    asan::AsanMode, csharp::CSharpMode, gdb::GdbMode, go::GoMode, java::JavaMode, js::JsMode,
    lua::LuaMode, msan::MsanMode, python::PythonMode, rust::RustMode, san::SanMode,
};

type RunResult = (Box<dyn ReportExtractor>, Box<dyn Mode>);

/// Auxiliary trait for making all language depended actions.
pub trait Mode: ModeClone + Send + Sync {
    /// Prepare environment to program running.
    fn pre_action(&self, _argv: &mut [String]) -> Result<()> {
        Ok(())
    }
    /// Modify command line as needed.
    fn update_cmd(&self, _cmd: &mut Command) -> Result<()> {
        Ok(())
    }
    /// Get corresponding `Runner` entry.
    fn get_runner(&self) -> Box<dyn Runner> {
        Box::new(StreamRunner {})
    }
    /// Get `RunResult` entry
    fn get_extractor(
        &self,
        _stdout: &str,
        _stderr: &str,
        _signal: Option<i32>,
    ) -> Result<Option<RunResult>> {
        Ok(None)
    }
    /// Get base `CrashReport` entry with filled common field.
    fn get_report_stub(&self, argv: &[String], stdin: &Option<PathBuf>) -> Result<CrashReport> {
        Ok(util::get_report_stub(argv, stdin))
    }
    /// Fill language depended CASR report field.
    fn fill_report(&self, _report: &mut CrashReport, _raw_report: Vec<String>) {}
    /// Fill CASR report `source` field if necessary,
    fn update_sources(
        &self,
        _report: &mut CrashReport,
        mut _debug: DebugInfo,
        _submatches: &Option<&ArgMatches>,
    ) {
    }
    /// Add exception info in CASR report if it exists.
    fn check_exception(&self, _report: &mut CrashReport, _stream: &str) {}
    /// Convert to `str`
    fn literal(&self) -> &str;
    /// Convert to `Any`
    fn as_any(&self) -> &dyn Any;
}

/// Auxiliary trait for `Mode` cloning
pub trait ModeClone {
    fn clone_box(&self) -> Box<dyn Mode>;
}

impl<T> ModeClone for T
where
    T: 'static + Mode + Clone,
{
    fn clone_box(&self) -> Box<dyn Mode> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn Mode> {
    fn clone(&self) -> Box<dyn Mode> {
        self.clone_box()
    }
}

/// Run program and extract CASR report info.
#[derive(Clone)]
pub struct DynMode {
    mode: Box<dyn Mode>,
}

impl DynMode {
    /// Create new entry
    pub fn new<T: Mode + Default + 'static>() -> Self {
        Self {
            mode: Box::new(T::default()),
        }
    }
    /// Prepare environment to program running.
    pub fn pre_action(&self, argv: &mut [String]) -> Result<()> {
        self.mode.pre_action(argv)
    }
    /// Modify command line as needed.
    pub fn update_cmd(&self, cmd: &mut Command) -> Result<()> {
        self.mode.update_cmd(cmd)
    }
    /// Get `ReportExtractor` entry
    pub fn get_extractor(
        &mut self,
        stdout: &str,
        stderr: &str,
        signal: Option<i32>,
    ) -> Result<Option<Box<dyn ReportExtractor>>> {
        let Some((extractor, mode)) = self.mode.get_extractor(stdout, stderr, signal)? else {
            return Ok(None);
        };
        self.mode = mode;
        Ok(Some(extractor))
    }
    /// Get base `CrashReport` entry with filled common field.
    pub fn get_report_stub(&self, argv: &[String], stdin: &Option<PathBuf>) -> Result<CrashReport> {
        self.mode.get_report_stub(argv, stdin)
    }
    /// Fill language depended CASR report field.
    pub fn fill_report(&self, report: &mut CrashReport, raw_report: Vec<String>) {
        self.mode.fill_report(report, raw_report)
    }
    /// Fill CASR report `source` field if necessary,
    pub fn update_sources(
        &self,
        report: &mut CrashReport,
        debug: DebugInfo,
        submatches: &Option<&ArgMatches>,
    ) {
        self.mode.update_sources(report, debug, submatches)
    }
    /// Add exception info in CASR report if it exists.
    pub fn check_exception(&self, report: &mut CrashReport, stream: &str) {
        self.mode.check_exception(report, stream)
    }
    /// Run target program
    pub fn run(
        &mut self,
        argv: &[String],
        stdin: &Option<PathBuf>,
        timeout: u64,
        ld_preload: &Option<String>,
    ) -> Result<(CrashReport, Box<dyn ReportExtractor>)> {
        let runner = self.mode.get_runner();
        if let Some(res) = runner.run(self, argv, stdin, timeout, ld_preload)? {
            Ok(res)
        } else {
            self.mode = Box::new(GdbMode {});
            let runner = Box::new(GdbRunner {});
            let res = runner.run(self, argv, stdin, timeout, ld_preload)?;
            Ok(res.unwrap())
        }
    }
    pub fn is_mode<T: Mode + 'static>(&self) -> bool {
        self.mode.as_any().downcast_ref::<T>().is_some()
    }
    pub fn is_gdb_compatible(&self) -> bool {
        self.is_mode::<AsanMode>()
            || self.is_mode::<GdbMode>()
            || self.is_mode::<GoMode>()
            || self.is_mode::<RustMode>()
            || self.is_mode::<MsanMode>()
            || self.is_mode::<SanMode>()
    }
}

impl TryFrom<&str> for DynMode {
    type Error = anyhow::Error;
    fn try_from(mode: &str) -> Result<Self> {
        let mode: Box<dyn Mode> = match mode {
            "asan" => Box::new(AsanMode::new()),
            "csharp" => Box::new(CSharpMode::new()),
            "gdb" => Box::new(GdbMode::new()),
            "go" => Box::new(GoMode::new()),
            "java" => Box::new(JavaMode::new()),
            "js" => Box::new(JsMode::new()),
            "lua" => Box::new(LuaMode::new()),
            "msan" => Box::new(MsanMode::new()),
            "python" => Box::new(PythonMode::new()),
            "rust" => Box::new(RustMode::new()),
            "san" => Box::new(SanMode::new()),
            _ => {
                bail!("Unexpected mode: {}", mode);
            }
        };
        Ok(Self { mode })
    }
}

impl TryFrom<(Option<&str>, &Vec<String>)> for DynMode {
    type Error = anyhow::Error;
    fn try_from((name, argv): (Option<&str>, &Vec<String>)) -> Result<Self> {
        if let Some(name) = name
            && name != "auto"
        {
            Self::try_from(name)
        } else if argv[0].ends_with("dotnet") || argv[0].ends_with("mono") {
            Ok(Self {
                mode: Box::new(CSharpMode::new()),
            })
        } else if argv[0].ends_with("jazzer") || argv[0].ends_with("java") {
            Ok(Self {
                mode: Box::new(JavaMode::new()),
            })
        } else if argv[0].ends_with(".js")
            || argv[0].ends_with("node")
            || argv[0].ends_with("jsfuzz")
            || argv.len() > 1 && argv[0].ends_with("npx") && argv[1] == "jazzer"
        {
            Ok(Self {
                mode: Box::new(JsMode::new()),
            })
        } else if argv[0].ends_with(".lua")
            || argv[0].starts_with("lua")
            || argv.len() > 1 && argv[1].ends_with(".lua")
        {
            Ok(Self {
                mode: Box::new(LuaMode::new()),
            })
        } else if argv[0].ends_with(".py")
            || argv[0].starts_with("python")
            || argv.len() > 1 && argv[1].ends_with(".py")
        {
            Ok(Self {
                mode: Box::new(PythonMode::new()),
            })
        } else {
            let sym_list = util::symbols_list(Path::new(&argv[0]))?;
            if sym_list.contains("__asan")
                || sym_list.contains("__msan")
                || sym_list.contains("runtime.go")
            {
                // NOTE: The exact mode can only be found out by parsing
                Ok(Self {
                    mode: Box::new(SanMode::new()),
                })
            } else {
                Ok(Self {
                    mode: Box::new(GdbMode::new()),
                })
            }
        }
    }
}

impl fmt::Debug for DynMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.mode.literal())
    }
}

impl fmt::Display for DynMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.mode.literal())
    }
}

impl Default for DynMode {
    fn default() -> Self {
        Self {
            mode: Box::new(GdbMode::new()),
        }
    }
}
