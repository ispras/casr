use crate::util;
use libcasr::{
    asan::AsanCrash,
    cpp::CppException,
    csharp::CSharpException,
    exception::Exception,
    gdb::GdbStacktrace,
    gdb::exploitable::{GdbContext, MachineInfo},
    go::GoPanic,
    init_ignored_frames,
    java::JavaException,
    js::JsException,
    lua::LuaException,
    msan::MsanCrash,
    python::PythonException,
    report::{CrashReport, ReportExtractor},
    rust::RustPanic,
    severity::Severity,
    stacktrace::{CrashLine, CrashLineExt, DebugInfo, Filter, ParseStacktrace, Stacktrace},
};

use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::ArgMatches;
use gdb_command::mappings::*;
use gdb_command::memory::*;
use gdb_command::registers::*;
use gdb_command::siginfo::Siginfo;
use gdb_command::stacktrace::StacktraceExt;
use gdb_command::*;
use goblin::container::Endian;
use goblin::elf::{Elf, header};
use regex::Regex;
use walkdir::WalkDir;

#[derive(Debug)]
pub enum Mode {
    Csharp,
    Gdb,
    Go,
    Java,
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
            "gdb" => Ok(Mode::Gdb),
            "go" => Ok(Mode::Go),
            "java" => Ok(Mode::Java),
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
    } else if argv[0].ends_with("jazzer")
        || argv[0].ends_with("java")
        || argv[0].ends_with("jsfuzz")
        || argv.len() > 1 && argv[0].ends_with("npx") && argv[1] == "jazzer"
    {
        Ok(Mode::Java)
    } else if argv[0].ends_with(".js") || argv[0].ends_with("node") {
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
            Ok(Mode::Gdb)
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

fn common_pipeline(
    matches: &ArgMatches,
    argv: &[String],
    stdin: &Option<PathBuf>,
    timeout: u64,
    ld_preload: &Option<String>,
    mode: &mut Mode,
) -> Result<Option<CrashReport>> {
    // Get subcommand args
    let submatches = if let Some(name) = matches.subcommand_name() {
        matches.subcommand_matches(name)
    } else {
        None
    };
    // Run program.
    let mut cmd = Command::new(&argv[0]);
    // Set ld preload
    if let Some(ld_preload) = ld_preload {
        cmd.env("LD_PRELOAD", ld_preload);
    }
    if let Some(file) = stdin {
        cmd.stdin(std::fs::File::open(file)?);
    }
    if argv.len() > 1 {
        cmd.args(&argv[1..]);
    }
    // Update mode-dependent characteristics
    update_cmd(&mut cmd, mode);
    // Get output
    let result = util::get_output(&mut cmd, timeout, true)?;
    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);
    let signal = result.status.signal();

    // Create report
    let mut report = get_report_stub(argv, stdin, mode)?;

    // Get report extractor
    let Some(mut extractor) = get_extractor(&stdout, &stderr, signal, mode)? else {
        return Ok(None);
    };

    // Extract report
    fill_report(&mut report, extractor.report(), mode);
    report.stacktrace = extractor.extract_stacktrace()?;
    if let Some(execution_class) = extractor.execution_class() {
        report.execution_class = execution_class;
    }
    if let Ok(crashline) = extractor.crash_line() {
        report.crashline = crashline.to_string();
        if let CrashLine::Source(debug) = crashline {
            if let Some(sources) = CrashReport::sources(&debug) {
                report.source = sources;
            }
            // Modify DebugInfo to find sources (for Java)
            update_sources(&mut report, debug, &submatches, mode);
        }
    }
    // Strip paths
    let stacktrace = extractor.parse_stacktrace()?;
    if let Some(path) = matches.get_one::<String>("strip-path") {
        util::strip_paths(&mut report, &stacktrace, path);
    }
    // Check for exceptions
    check_exception(&mut report, &stderr, mode);

    Ok(Some(report))
}

fn gdb_pipeline(
    matches: &ArgMatches,
    argv: &[String],
    stdin: &Option<PathBuf>,
    timeout: u64,
    _ld_preload: &Option<String>, // TODO: Add support
    mode: &mut Mode,
) -> Result<CrashReport> {
    let target_path = PathBuf::from(argv[0].clone());
    if !target_path.exists() {
        bail!("{} doesn't exist", target_path.to_str().unwrap());
    }
    // Prepare machine context
    let mut header = vec![0u8; 64];
    // The ELF header is 52 or 64 bytes long for 32-bit and 64-bit binaries respectively.
    let mut file = File::open(&target_path)
        .with_context(|| format!("Couldn't open target binary: {}", target_path.display()))?;
    file.read_exact(&mut header).with_context(|| {
        format!(
            "Couldn't read target binary header: {}",
            target_path.display()
        )
    })?;
    // Elf header
    let elf_h = Elf::parse_header(&header).with_context(|| {
        format!(
            "Couldn't header for target binary: {}",
            target_path.display()
        )
    })?;
    // Machine info
    let mut machine = MachineInfo {
        arch: header::EM_X86_64,
        endianness: Endian::Little,
        byte_width: 8,
    };
    // Type should be executable or shared object.
    if elf_h.e_type != header::ET_EXEC && elf_h.e_type != header::ET_DYN {
        bail!("Target binary type should be executable or shared object");
    }
    // Byte width
    match elf_h.e_ident[4] {
        1 => machine.byte_width = 4,
        2 => machine.byte_width = 8,
        _ => {
            bail!("Couldn't determine byte_width: {}", elf_h.e_ident[4]);
        }
    }
    // Endianness
    if let Ok(endianness) = elf_h.endianness() {
        machine.endianness = endianness;
    } else {
        bail!("Couldn't get endianness from target binary");
    }
    // Architecture
    match elf_h.e_machine {
        header::EM_386
        | header::EM_ARM
        | header::EM_X86_64
        | header::EM_AARCH64
        | header::EM_RISCV => machine.arch = elf_h.e_machine,
        _ => {
            bail!("Unsupported architecture: {}", elf_h.e_machine);
        }
    }

    // Run gdb
    let args: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    let exectype = ExecType::Local(&args);
    let mut gdb_command = GdbCommand::new(&exectype);
    let gdb_command = gdb_command
        .timeout(timeout)
        .stdin(stdin)
        .r()
        .bt()
        .siginfo()
        .mappings()
        .regs()
        // We need 2 disassembles: one for severity analysis
        // and another for the report.
        .mem("$pc", 64)
        .disassembly();

    // Get output
    let stdout = gdb_command
        .raw()
        .with_context(|| "Unable to get results from gdb")?;
    let output = String::from_utf8_lossy(&stdout);
    let result = gdb_command.parse(&output)?;

    // Create report
    let mut report = get_report_stub(argv, stdin, mode)?;

    // Fill report
    report.stacktrace = GdbStacktrace::extract_stacktrace(&result[0])?;
    report.proc_maps = result[2]
        .split('\n')
        .skip(3)
        .map(|x| x.to_string())
        .collect();

    let siginfo = Siginfo::from_gdb(&result[1]);
    if let Err(error) = siginfo {
        let err_str = error.to_string();
        let re = Regex::new(r"\$\d+ = (0x0|void) doesn't match regex template").unwrap();
        if err_str.contains(":  doesn't match") || re.is_match(&err_str) {
            // Normal termination.
            bail!("Program terminated (no crash)");
        } else {
            return Err(error.into());
        }
    }

    let context = GdbContext {
        siginfo: siginfo.unwrap(),
        mappings: MappedFiles::from_gdb(&result[2])?,
        registers: Registers::from_gdb(&result[3])?,
        pc_memory: MemoryObject::from_gdb(&result[4])?,
        machine,
        stacktrace: report.stacktrace.clone(),
    };

    report.set_disassembly(&result[5]);

    let severity = context.severity();

    if let Ok(severity) = severity {
        report.execution_class = severity;
    } else {
        eprintln!("Couldn't estimate severity. {}", severity.err().unwrap());
    }

    report.registers = context.registers;

    let mut stacktrace = GdbStacktrace::parse_stacktrace(&report.stacktrace)?;
    if let Ok(mfiles) = MappedFiles::from_gdb(report.proc_maps.join("\n")) {
        stacktrace.compute_module_offsets(&mfiles);
    }
    // Get crash line.
    if let Ok(crashline) = stacktrace.crash_line() {
        report.crashline = crashline.to_string();
        if let CrashLine::Source(debug) = crashline {
            if let Some(sources) = CrashReport::sources(&debug) {
                report.source = sources;
            }
        }
    }

    // Check for exceptions
    if let Some(path) = matches.get_one::<String>("strip-path") {
        util::strip_paths(&mut report, &stacktrace, path);
    }
    // Check for exceptions
    check_exception(&mut report, &output, mode);

    Ok(report)
}

pub fn pipeline(
    matches: &ArgMatches,
    argv: &[String],
    stdin: &Option<PathBuf>,
    timeout: u64,
    ld_preload: &Option<String>,
    mode: &mut Mode,
) -> Result<CrashReport> {
    if let Mode::Gdb = mode {
        gdb_pipeline(matches, argv, stdin, timeout, ld_preload, mode)
    } else if let Some(report) = common_pipeline(matches, argv, stdin, timeout, ld_preload, mode)? {
        Ok(report)
    } else {
        gdb_pipeline(matches, argv, stdin, timeout, ld_preload, mode)
    }
}
