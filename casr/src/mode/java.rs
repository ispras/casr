use std::{any::Any, path::PathBuf, process::Command};

use anyhow::{Result, bail};
use clap::ArgMatches;
use gdb_command::stacktrace::DebugInfo;
use walkdir::WalkDir;

use libcasr::{
    init_ignored_frames,
    java::JavaException,
    report::CrashReport,
    stacktrace::{Filter, Stacktrace},
};

use crate::util;

use super::{Mode, RunResult, san::SanMode};

// TODO: docs
#[derive(Clone, Debug, Default)]
pub struct JavaMode {
    san: SanMode,
}

impl JavaMode {
    pub fn new() -> Self {
        Self { san: SanMode {} }
    }
}

impl Mode for JavaMode {
    fn pre_action(&self, _argv: &mut [String]) -> Result<()> {
        init_ignored_frames!("cpp", "java");
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
        if let Some(exception) = JavaException::new(stderr)? {
            Ok(Some((Box::new(exception), Box::new(Self::new()))))
        } else {
            self.san.get_san_extractor(stderr, signal)
        }
    }
    fn get_report_stub(&self, argv: &[String], stdin: &Option<PathBuf>) -> Result<CrashReport> {
        let mut report = util::get_report_stub(argv, stdin);
        // Set executable path (java class path)
        if let Some(pos) = argv.iter().position(|arg| {
            arg.starts_with("-cp")
                || arg.starts_with("--cp")
                || arg.starts_with("-class-path")
                || arg.starts_with("--classpath")
        }) {
            report.executable_path = if let Some(classes) = argv[pos].split('=').nth(1) {
                classes
            } else {
                let Some(classes) = argv.get(pos + 1) else {
                    bail!("Class path is empty.");
                };
                classes
            }
            .to_string();
        }
        Ok(report)
    }
    fn fill_report(&self, report: &mut CrashReport, raw_report: Vec<String>) {
        report.java_report = raw_report;
    }
    fn update_sources(
        &self,
        report: &mut CrashReport,
        mut debug: DebugInfo,
        submatches: &Option<&ArgMatches>,
    ) {
        let source_dirs = if let Some(submatches) = submatches {
            if let Some(sources) = submatches.get_many::<PathBuf>("source-dirs") {
                sources.collect()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        if let Some(file) = source_dirs.iter().find_map(|dir| {
            WalkDir::new(dir)
                .into_iter()
                .flatten()
                .map(|e| e.into_path())
                .filter(|e| e.is_file())
                .filter(|e| e.extension().is_some() && e.extension().unwrap() == "java")
                .find(|x| {
                    x.file_name()
                        .unwrap()
                        .eq(PathBuf::from(&debug.file).file_name().unwrap())
                })
        }) {
            debug.file = file.display().to_string();
        }
        if let Some(sources) = CrashReport::sources(&debug) {
            report.source = sources;
        }
    }
    fn literal(&self) -> &str {
        "java"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
