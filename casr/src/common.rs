use crate::util;
use libcasr::{
    asan::AsanCrash,
    csharp::CSharpException,
    go::GoPanic,
    init_ignored_frames,
    js::JsException,
    lua::LuaException,
    msan::MsanCrash,
    python::PythonException,
    report::{CrashReport, ReportExtractor},
    rust::RustPanic,
    stacktrace::{Filter, Stacktrace},
};

use anyhow::{Result, bail};
use clap::ArgMatches;

use std::env;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug)]
pub enum Mode {
    Csharp,
    Go,
    Js,
    Lua,
    Python,
    Rust,
    San, // Intermediate mode
    Asan,
    Msan,
}

impl Mode {
    fn new(mode: &str) -> Result<Mode> {
        match mode {
            "csharp" => Ok(Mode::Csharp),
            "go" => Ok(Mode::Go),
            "js" => Ok(Mode::Js),
            "lua" => Ok(Mode::Lua),
            "python" => Ok(Mode::Python),
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

pub fn get_mode(matches: &ArgMatches, argv: &[String]) -> Result<Mode> {
    let subcommand = matches.subcommand_name();
    if subcommand.is_some() && subcommand.unwrap() != "auto" {
        Ok(Mode::new(subcommand.unwrap())?)
    } else if argv[0].ends_with("dotnet") || argv[0].ends_with("mono") {
        Ok(Mode::Csharp)
    } else if argv[0].ends_with(".js")
        || argv[0].ends_with("node")
        || argv[0].ends_with("jsfuzz")
        || argv.len() > 1 && argv[0].ends_with("npx") && argv[1] == "jazzer"
    {
        Ok(Mode::Js)
    } else if argv[0].ends_with(".lua")
        || argv[0].starts_with("lua")
        || argv.len() > 1 && argv[1].ends_with(".lua")
    {
        Ok(Mode::Lua)
    } else if argv[0].ends_with(".py")
        || argv[0].starts_with("python")
        || argv.len() > 1 && argv[1].ends_with(".py")
    {
        Ok(Mode::Python)
    } else {
        let sym_list = util::symbols_list(Path::new(&argv[0]))?;
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

fn prepare_run_csharp(argv: &[String]) -> Result<()> {
    // Check that args are valid.
    if !argv
        .iter()
        .any(|x| x.ends_with(".dll") || x.ends_with(".exe") || x.ends_with(".csproj"))
    {
        bail!("dotnet/mono target is not specified by .dll, .exe or .csproj executable.");
    };
    Ok(())
}

fn prepare_run_js(argv: &mut [String]) -> Result<()> {
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
    Ok(())
}

pub fn prepare_run(argv: &mut [String], mode: &Mode) -> Result<()> {
    match mode {
        Mode::Csharp => {
            prepare_run_csharp(argv)?;
            init_ignored_frames!("csharp", "cpp");
        }
        Mode::Go => {
            init_ignored_frames!("cpp", "go");
        }
        Mode::Js => {
            prepare_run_js(argv)?;
            init_ignored_frames!("cpp", "js");
        }
        Mode::Lua => {
            init_ignored_frames!("lua");
        }
        Mode::Python => {
            init_ignored_frames!("cpp", "python");
        }
        Mode::Rust => {
            init_ignored_frames!("cpp", "rust");
        }
        Mode::San => {
            init_ignored_frames!("cpp", "go", "rust");
        }
        Mode::Asan | Mode::Msan => {
            init_ignored_frames!("cpp");
        }
    }
    Ok(())
}

fn update_cmd_san(cmd: &mut Command) {
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
}

pub fn update_cmd(cmd: &mut Command, mode: &Mode) {
    match mode {
        Mode::San | Mode::Asan | Mode::Msan | Mode::Csharp | Mode::Go | Mode::Rust => {
            update_cmd_san(cmd);
        }
        _ => {}
    }
}

fn update_report_stub_csharp(report: &mut CrashReport, argv: &[String]) {
    // Set executable path (for C# .dll, .csproj (dotnet) or .exe (mono) file).
    let pos = argv
        .iter()
        .position(|x| x.ends_with(".dll") || x.ends_with(".exe") || x.ends_with(".csproj"))
        .unwrap();
    report.executable_path = argv.get(pos).unwrap().to_string();
}

fn update_report_stub_lua(report: &mut CrashReport, argv: &[String]) {
    if argv.len() > 1 {
        if let Some(fname) = Path::new(&argv[0]).file_name() {
            let fname = fname.to_string_lossy();
            if fname.starts_with("lua") && !fname.ends_with(".lua") && argv[1].ends_with(".lua") {
                report.executable_path = argv[1].to_string();
            }
        }
    }
}

fn update_report_stub_js(report: &mut CrashReport, argv: &[String]) {
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
}

fn update_report_stub_python(report: &mut CrashReport, argv: &[String]) {
    if argv.len() > 1 {
        if let Some(fname) = Path::new(&argv[0]).file_name() {
            let fname = fname.to_string_lossy();
            if fname.starts_with("python") && !fname.ends_with(".py") && argv[1].ends_with(".py") {
                report.executable_path = argv[1].to_string();
            }
        }
    }
}

fn update_report_stub_san(report: &mut CrashReport, stdin: &Option<PathBuf>) {
    if let Some(mut file_path) = stdin.clone() {
        file_path = file_path.canonicalize().unwrap_or(file_path);
        report.stdin = file_path.display().to_string();
    }
}

pub fn get_report_stub(argv: &[String], stdin: &Option<PathBuf>, mode: &Mode) -> CrashReport {
    let mut report = CrashReport::new();
    report.executable_path = argv[0].to_string();
    report.proc_cmdline = argv.join(" ");
    let _ = report.add_os_info();
    let _ = report.add_proc_environ();
    match mode {
        Mode::Csharp => {
            update_report_stub_csharp(&mut report, argv);
        }
        Mode::Js => {
            update_report_stub_js(&mut report, argv);
        }
        Mode::Lua => {
            update_report_stub_lua(&mut report, argv);
        }
        Mode::Python => {
            update_report_stub_python(&mut report, argv);
        }
        Mode::San | Mode::Asan | Mode::Msan | Mode::Go | Mode::Rust => {
            update_report_stub_san(&mut report, stdin);
        }
    }
    report
}

fn get_san_extractor(stderr: &str, mode: &mut Mode) -> Result<Box<dyn ReportExtractor>> {
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
fn get_legacy_san_extractor(stderr: &str, mode: &mut Mode) -> Result<Box<dyn ReportExtractor>> {
    if let Some(panic) = GoPanic::new(stderr) {
        *mode = Mode::Go;
        Ok(Box::new(panic))
    } else if let Some(panic) = RustPanic::new(stderr) {
        *mode = Mode::Rust;
        Ok(Box::new(panic))
    } else {
        get_san_extractor(stderr, mode)
    }
}

pub fn get_extractor(
    stdout: &str,
    stderr: &str,
    mode: &mut Mode,
) -> Result<Box<dyn ReportExtractor>> {
    match mode {
        Mode::Csharp => {
            if let Some(exception) = CSharpException::new(stderr)? {
                Ok(Box::new(exception))
            } else {
                get_san_extractor(stderr, mode)
            }
        }
        Mode::Go => {
            if let Some(panic) = GoPanic::new(stderr) {
                Ok(Box::new(panic))
            } else {
                get_san_extractor(stderr, mode)
            }
        }
        Mode::Js => {
            if let Some(exception) = JsException::new(stderr)? {
                Ok(Box::new(exception))
            } else {
                get_san_extractor(stderr, mode)
            }
        }
        Mode::Lua => {
            let Some(exception) = LuaException::new(stderr) else {
                bail!("Lua exception is not found!");
            };
            Ok(Box::new(exception))
        }
        Mode::Python => {
            if let Some(exception) = PythonException::new(stdout, stderr)? {
                Ok(Box::new(exception))
            } else {
                get_san_extractor(stderr, mode)
            }
        }
        Mode::Rust => {
            if let Some(panic) = RustPanic::new(stderr) {
                Ok(Box::new(panic))
            } else {
                get_san_extractor(stderr, mode)
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
        Mode::San => get_legacy_san_extractor(stderr, mode),
    }
}

// NOTE: if there were no different report fields this function would not be needed
pub fn fill_report(report: &mut CrashReport, raw_report: Vec<String>, mode: &Mode) {
    match mode {
        Mode::Csharp => {
            report.csharp_report = raw_report;
        }
        Mode::Go => {
            report.go_report = raw_report;
        }
        Mode::Js => {
            report.js_report = raw_report;
        }
        Mode::Lua => {
            report.lua_report = raw_report;
        }
        Mode::Python => {
            report.python_report = raw_report;
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
