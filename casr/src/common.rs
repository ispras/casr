use crate::util;
use libcasr::{
    asan::AsanCrash,
    go::GoPanic,
    lua::LuaException,
    msan::MsanCrash,
    report::{CrashReport, ReportExtractor},
    rust::RustPanic,
};

use anyhow::{Result, bail};
use clap::ArgMatches;

use std::env;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug)]
pub enum Mode {
    Go,
    Lua,
    Rust,
    San, // Intermediate mode
    Asan,
    Msan,
}

impl Mode {
    fn new(mode: &str) -> Result<Mode> {
        match mode {
            "go" => Ok(Mode::Go),
            "lua" => Ok(Mode::Lua),
            "rust" => Ok(Mode::Rust),
            "san" => Ok(Mode::San),
            "asan" => Ok(Mode::Asan),
            "msan" => Ok(Mode::Msan),
            _ => {
                bail!("Unexpected mode: {}", mode);
            }
        }
    }
}

pub fn get_mode(matches: &ArgMatches, argv: &[&str]) -> Result<Mode> {
    let subcommand = matches.subcommand_name();
    if subcommand.is_some() && subcommand.unwrap() != "auto" {
        Ok(Mode::new(subcommand.unwrap())?)
    } else if argv[0].ends_with(".lua") {
        Ok(Mode::Lua)
    } else {
        let sym_list = util::symbols_list(Path::new(argv[0]))?;
        if sym_list.contains("__asan")
            || sym_list.contains("__msan")
            || sym_list.contains("runtime.go")
        {
            // NOTE: The exact mode can only be found out by parsing
            Ok(Mode::San)
        } else {
            // TODO: gdb
            bail!("PLACEME");
        }
    }
}

pub fn prepare_run_san() {
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
        unsafe {
            std::env::set_var("ASAN_OPTIONS", asan_options);
        }
    } else {
        unsafe {
            std::env::set_var("ASAN_OPTIONS", "hard_rss_limit_mb=2048");
        }
    }
}

pub fn prepare_run(mode: &Mode) {
    match mode {
        Mode::San | Mode::Asan | Mode::Msan | Mode::Go | Mode::Rust => {
            prepare_run_san();
        }
        _ => {}
    }
}

pub fn update_cmd_san(cmd: &mut Command) {
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
}

pub fn update_cmd(cmd: &mut Command, mode: &Mode) {
    match mode {
        Mode::San | Mode::Asan | Mode::Msan | Mode::Go | Mode::Rust => {
            update_cmd_san(cmd);
        }
        _ => {}
    }
}

pub fn update_report_stub_lua(report: &mut CrashReport, argv: &[&str]) {
    if argv.len() > 1 {
        if let Some(fname) = Path::new(argv[0]).file_name() {
            let fname = fname.to_string_lossy();
            if fname.starts_with("lua") && !fname.ends_with(".lua") && argv[1].ends_with(".lua") {
                report.executable_path = argv[1].to_string();
            }
        }
    }
}

pub fn update_report_stub_san(report: &mut CrashReport, stdin_file: &Option<PathBuf>) {
    if let Some(mut file_path) = stdin_file.clone() {
        file_path = file_path.canonicalize().unwrap_or(file_path);
        report.stdin = file_path.display().to_string();
    }
}

pub fn get_report_stub(argv: &Vec<&str>, stdin_file: &Option<PathBuf>, mode: &Mode) -> CrashReport {
    let mut report = CrashReport::new();
    report.executable_path = argv[0].to_string();
    report.proc_cmdline = argv.join(" ");
    let _ = report.add_os_info();
    let _ = report.add_proc_environ();
    match mode {
        Mode::Lua => {
            update_report_stub_lua(&mut report, argv);
        }
        Mode::San | Mode::Asan | Mode::Msan | Mode::Go | Mode::Rust => {
            update_report_stub_san(&mut report, stdin_file);
        }
    }
    report
}

pub fn get_san_extractor(
    _stdout: &str,
    stderr: &str,
    mode: &mut Mode,
) -> Result<Box<dyn ReportExtractor>> {
    if let Some(crash) = AsanCrash::new(stderr)? {
        *mode = Mode::Asan;
        Ok(Box::new(crash))
    } else if let Some(crash) = MsanCrash::new(stderr)? {
        *mode = Mode::Msan;
        Ok(Box::new(crash))
    } else {
        // TODO: signal
        // Normal termination
        bail!("Program terminated (no crash)");
    }
}

// Add only for backward compatibility: casr-san could parse Go and Rust Panics
pub fn get_legacy_san_extractor(
    stdout: &str,
    stderr: &str,
    mode: &mut Mode,
) -> Result<Box<dyn ReportExtractor>> {
    if let Some(panic) = GoPanic::new(stderr) {
        *mode = Mode::Go;
        Ok(Box::new(panic))
    } else if let Some(panic) = RustPanic::new(stderr) {
        *mode = Mode::Rust;
        Ok(Box::new(panic))
    } else {
        get_san_extractor(stdout, stderr, mode)
    }
}

pub fn get_extractor(
    stdout: &str,
    stderr: &str,
    mode: &mut Mode,
) -> Result<Box<dyn ReportExtractor>> {
    match mode {
        Mode::Go => {
            if let Some(panic) = GoPanic::new(stderr) {
                Ok(Box::new(panic))
            } else {
                get_san_extractor(stdout, stderr, mode)
            }
        }
        Mode::Lua => {
            let Some(exception) = LuaException::new(stderr) else {
                bail!("Lua exception is not found!");
            };
            Ok(Box::new(exception))
        }
        Mode::Rust => {
            if let Some(panic) = RustPanic::new(stderr) {
                Ok(Box::new(panic))
            } else {
                get_san_extractor(stdout, stderr, mode)
            }
        }
        Mode::Asan => {
            let Some(crash) = AsanCrash::new(stderr)? else {
                bail!("AddressSanitizer crash is not found!");
            };
            Ok(Box::new(crash))
        }
        Mode::Msan => {
            let Some(crash) = MsanCrash::new(stderr)? else {
                bail!("MemorySanitizer crash is not found!");
            };
            Ok(Box::new(crash))
        }
        Mode::San => get_legacy_san_extractor(stdout, stderr, mode),
    }
}

// NOTE: if there were no different report fields this function would not be needed
pub fn fill_report(report: &mut CrashReport, raw_report: Vec<String>, mode: &Mode) {
    match mode {
        Mode::Go => {
            report.go_report = raw_report;
        }
        Mode::Lua => {
            report.lua_report = raw_report;
        }
        Mode::Rust => {
            report.rust_report = raw_report;
        }
        Mode::Asan => {
            report.asan_report = raw_report;
        }
        Mode::Msan => {
            report.msan_report = raw_report;
        }
        Mode::San => {
            // Impossible to be there
        }
    }
}
