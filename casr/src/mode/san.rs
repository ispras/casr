use std::{any::Any, env, os::unix::process::CommandExt, process::Command};

use anyhow::{Result, bail};

use libcasr::{
    asan::AsanCrash,
    go::GoPanic,
    init_ignored_frames,
    msan::MsanCrash,
    report::CrashReport,
    rust::RustPanic,
    stacktrace::{Filter, Stacktrace},
};

use crate::util;

use super::{Mode, RunResult, asan::AsanMode, go::GoMode, msan::MsanMode, rust::RustMode};

// TODO: docs
#[derive(Clone, Debug, Default)]
pub struct SanMode {}

impl SanMode {
    pub fn new() -> Self {
        Default::default()
    }
}

impl SanMode {
    pub fn get_san_extractor(
        &self,
        stderr: &str,
        signal: Option<i32>,
    ) -> Result<Option<RunResult>> {
        if let Some(crash) = AsanCrash::new(stderr)? {
            Ok(Some((Box::new(crash), Box::new(AsanMode::new()))))
        } else if let Some(crash) = MsanCrash::new(stderr)? {
            Ok(Some((Box::new(crash), Box::new(MsanMode::new()))))
        } else if signal.is_some() {
            // NOTE: Hack for rerunning with gdb
            Ok(None)
        } else {
            // Normal termination
            bail!("Program terminated (no crash)");
        }
    }
}

impl Mode for SanMode {
    fn pre_action(&self, _argv: &mut [String]) -> Result<()> {
        init_ignored_frames!("cpp", "go", "rust");
        Ok(())
    }
    fn update_cmd(&self, cmd: &mut Command) -> Result<()> {
        // Set rss limit.
        if let Ok(asan_options_str) = env::var("ASAN_OPTIONS") {
            let mut asan_options = asan_options_str.clone();
            if !asan_options_str.contains("hard_rss_limit_mb") {
                asan_options = [asan_options.as_str(), "hard_rss_limit_mb=2048"].join(",");
            }
            if asan_options.starts_with(',') {
                asan_options.remove(0);
            }
            asan_options = asan_options.replace("symbolize=0", "symbolize=1");
            cmd.env("ASAN_OPTIONS", asan_options);
        } else {
            cmd.env("ASAN_OPTIONS", "hard_rss_limit_mb=2048");
        }

        #[cfg(target_os = "macos")]
        {
            cmd.env("DYLD_NO_PIE", "1");
        }
        #[cfg(target_os = "linux")]
        {
            use linux_personality::{Personality, personality};

            unsafe {
                cmd.pre_exec(|| {
                    if personality(Personality::ADDR_NO_RANDOMIZE).is_err() {
                        panic!("Cannot set personality");
                    }
                    Ok(())
                })
            };
        }
        Ok(())
    }
    fn get_extractor(
        &self,
        _stdout: &str,
        stderr: &str,
        signal: Option<i32>,
    ) -> Result<Option<RunResult>> {
        if let Some(panic) = GoPanic::new(stderr) {
            Ok(Some((Box::new(panic), Box::new(GoMode::new()))))
        } else if let Some(panic) = RustPanic::new(stderr) {
            Ok(Some((Box::new(panic), Box::new(RustMode::new()))))
        } else {
            self.get_san_extractor(stderr, signal)
        }
    }
    fn check_exception(&self, report: &mut CrashReport, stream: &str) {
        util::check_exception(report, stream)
    }
    fn literal(&self) -> &str {
        "san"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
