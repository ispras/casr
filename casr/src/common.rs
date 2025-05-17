use crate::mode::Mode;

use libcasr::{
    asan::AsanCrash,
    cpp::CppException,
    csharp::CSharpException,
    exception::Exception,
    go::GoPanic,
    init_ignored_frames,
    java::JavaException,
    js::JsException,
    lua::LuaException,
    msan::MsanCrash,
    python::PythonException,
    report::{CrashReport, ReportExtractor},
    rust::RustPanic,
    stacktrace::{DebugInfo, Filter, Stacktrace},
};

use std::env;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Result, bail};
use clap::ArgMatches;
use walkdir::WalkDir;

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
        Mode::Asan | Mode::Msan => {
            init_ignored_frames!("cpp");
        }
        Mode::Csharp => {
            prepare_run_csharp(argv)?;
            init_ignored_frames!("csharp", "cpp");
        }
        Mode::Gdb | Mode::Rust => {
            init_ignored_frames!("cpp", "rust");
        }
        Mode::Go => {
            init_ignored_frames!("cpp", "go");
        }
        Mode::Java => {
            init_ignored_frames!("cpp", "java");
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
        Mode::San => {
            init_ignored_frames!("cpp", "go", "rust");
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

fn update_report_stub_java(report: &mut CrashReport, argv: &[String]) -> Result<()> {
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
    Ok(())
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

pub fn get_report_stub(
    argv: &[String],
    stdin: &Option<PathBuf>,
    mode: &Mode,
) -> Result<CrashReport> {
    let mut report = CrashReport::new();
    report.executable_path = argv[0].to_string();
    report.proc_cmdline = argv.join(" ");
    let _ = report.add_os_info();
    let _ = report.add_proc_environ();
    if let Some(mut file_path) = stdin.clone() {
        file_path = file_path.canonicalize().unwrap_or(file_path);
        report.stdin = file_path.display().to_string();
    }
    match mode {
        Mode::Csharp => {
            update_report_stub_csharp(&mut report, argv);
        }
        Mode::Java => {
            update_report_stub_java(&mut report, argv)?;
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
        _ => {}
    }
    Ok(report)
}

fn get_san_extractor(
    stderr: &str,
    signal: Option<i32>,
    mode: &mut Mode,
) -> Result<Option<Box<dyn ReportExtractor>>> {
    if let Some(crash) = AsanCrash::new(stderr)? {
        *mode = Mode::Asan;
        Ok(Some(Box::new(crash)))
    } else if let Some(crash) = MsanCrash::new(stderr)? {
        *mode = Mode::Msan;
        Ok(Some(Box::new(crash)))
    } else if signal.is_some() {
        *mode = Mode::Gdb;
        // NOTE: Hack
        Ok(None)
    } else {
        // Normal termination
        bail!("Program terminated (no crash)");
    }
}

// Add only for backward compatibility: casr-san could parse Go and Rust Panics
fn get_legacy_san_extractor(
    stderr: &str,
    signal: Option<i32>,
    mode: &mut Mode,
) -> Result<Option<Box<dyn ReportExtractor>>> {
    if let Some(panic) = GoPanic::new(stderr) {
        *mode = Mode::Go;
        Ok(Some(Box::new(panic)))
    } else if let Some(panic) = RustPanic::new(stderr) {
        *mode = Mode::Rust;
        Ok(Some(Box::new(panic)))
    } else {
        get_san_extractor(stderr, signal, mode)
    }
}

pub fn get_extractor(
    stdout: &str,
    stderr: &str,
    signal: Option<i32>,
    mode: &mut Mode,
) -> Result<Option<Box<dyn ReportExtractor>>> {
    match mode {
        Mode::Csharp => {
            if let Some(exception) = CSharpException::new(stderr)? {
                Ok(Some(Box::new(exception)))
            } else {
                get_san_extractor(stderr, signal, mode)
            }
        }
        Mode::Gdb => {
            bail!("Unsupported extractor!");
        }
        Mode::Go => {
            if let Some(panic) = GoPanic::new(stderr) {
                Ok(Some(Box::new(panic)))
            } else {
                get_san_extractor(stderr, signal, mode)
            }
        }
        Mode::Java => {
            if let Some(exception) = JavaException::new(stderr)? {
                Ok(Some(Box::new(exception)))
            } else {
                get_san_extractor(stderr, signal, mode)
            }
        }
        Mode::Js => {
            if let Some(exception) = JsException::new(stderr)? {
                Ok(Some(Box::new(exception)))
            } else {
                get_san_extractor(stderr, signal, mode)
            }
        }
        Mode::Lua => {
            let Some(exception) = LuaException::new(stderr) else {
                bail!("Lua exception is not found!");
            };
            Ok(Some(Box::new(exception)))
        }
        Mode::Python => {
            if let Some(exception) = PythonException::new(stdout, stderr)? {
                Ok(Some(Box::new(exception)))
            } else {
                get_san_extractor(stderr, signal, mode)
            }
        }
        Mode::Rust => {
            if let Some(panic) = RustPanic::new(stderr) {
                Ok(Some(Box::new(panic)))
            } else {
                get_san_extractor(stderr, signal, mode)
            }
        }
        Mode::Asan => {
            let Some(crash) = AsanCrash::new(stderr)? else {
                bail!("AddressSanitizer crash is not found!");
            };
            Ok(Some(Box::new(crash)))
        }
        Mode::Msan => {
            let Some(crash) = MsanCrash::new(stderr)? else {
                bail!("MemorySanitizer crash is not found!");
            };
            Ok(Some(Box::new(crash)))
        }
        Mode::San => get_legacy_san_extractor(stderr, signal, mode),
    }
}

// NOTE: if there were no different report fields this function would not be needed
pub fn fill_report(report: &mut CrashReport, raw_report: Vec<String>, mode: &Mode) {
    match mode {
        Mode::Csharp => {
            report.csharp_report = raw_report;
        }
        Mode::Gdb => {}
        Mode::Go => {
            report.go_report = raw_report;
        }
        Mode::Js => {
            report.js_report = raw_report;
        }
        Mode::Java => {
            report.java_report = raw_report;
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

pub fn update_sources(
    report: &mut CrashReport,
    mut debug: DebugInfo,
    submatches: &Option<&ArgMatches>,
    mode: &Mode,
) {
    if let Mode::Java = mode {
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
}

pub fn check_exception(report: &mut CrashReport, stream: &str, mode: &Mode) {
    match mode {
        Mode::Asan | Mode::Msan | Mode::Gdb | Mode::Rust => {
            if let Some(class) = [CppException::parse_exception, RustPanic::parse_exception]
                .iter()
                .find_map(|parse| parse(stream))
            {
                report.execution_class = class;
            }
        }
        _ => {}
    }
}
