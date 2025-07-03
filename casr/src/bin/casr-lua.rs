use casr::util;
use libcasr::{
    init_ignored_frames,
    lua::LuaException,
    report::CrashReport,
    severity::Severity,
    stacktrace::Filter,
    stacktrace::Stacktrace,
    stacktrace::{CrashLine, CrashLineExt},
};

use anyhow::{Result, bail};
use clap::{Arg, ArgAction, ArgGroup};
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() -> Result<()> {
    let matches = clap::Command::new("casr-lua")
        .version(clap::crate_version!())
        .about("Create CASR reports (.casrep) from Lua reports")
        .term_width(90)
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .value_name("REPORT")
                .help(
                    "Path to save report. Path can be a directory, then report name is generated",
                ),
        )
        .arg(
            Arg::new("stdout")
                .action(ArgAction::SetTrue)
                .long("stdout")
                .help("Print CASR report to stdout"),
        )
        .group(
            ArgGroup::new("out")
                .args(["stdout", "output"])
                .required(true),
        )
        .arg(
            Arg::new("stdin")
                .long("stdin")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .value_name("FILE")
                .help("Stdin file for program"),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .action(ArgAction::Set)
                .default_value("0")
                .value_name("SECONDS")
                .help("Timeout (in seconds) for target execution, 0 value means that timeout is disabled")
                .value_parser(clap::value_parser!(u64))
        )
        .arg(
            Arg::new("ignore")
                .long("ignore")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .value_name("FILE")
                .help("File with regular expressions for functions and file paths that should be ignored"),
        )
        .arg(
            Arg::new("strip-path")
                .long("strip-path")
                .env("CASR_STRIP_PATH")
                .action(ArgAction::Set)
                .value_name("PREFIX")
                .help("Path prefix to strip from stacktrace"),
        )
        .arg(
            Arg::new("ld-preload")
                .long("ld-preload")
                .env("CASR_PRELOAD")
                .action(ArgAction::Set)
                .num_args(1..)
                .value_name("LIBS")
                .value_parser(clap::value_parser!(String))
                .help("Set LD_PRELOAD for the target program without disrupting the CASR process itself (both ` ` and `:` are valid delimiter)")
        )
        .arg(
            Arg::new("ARGS")
                .action(ArgAction::Set)
                .num_args(1..)
                .last(true)
                .required(true)
                .help("Add \"-- <path> <arguments>\" to run"),
        )
        .get_matches();

    init_ignored_frames!("lua");
    if let Some(path) = matches.get_one::<PathBuf>("ignore") {
        util::add_custom_ignored_frames(path)?;
    }
    // Get program args.
    let argv: Vec<&str> = if let Some(argvs) = matches.get_many::<String>("ARGS") {
        argvs.map(|s| s.as_str()).collect()
    } else {
        bail!("Wrong arguments for starting program");
    };

    // Get stdin for target program.
    let stdin_file = util::stdin_from_matches(&matches)?;

    // Get timeout
    let timeout = *matches.get_one::<u64>("timeout").unwrap();

    // Run program.
    let mut cmd = Command::new(argv[0]);
    // Set ld preload
    if let Some(ld_preload) = util::get_ld_preload(&matches) {
        cmd.env("LD_PRELOAD", ld_preload);
    }
    if let Some(ref file) = stdin_file {
        cmd.stdin(std::fs::File::open(file)?);
    }
    if argv.len() > 1 {
        cmd.args(&argv[1..]);
    }
    let result = util::get_output(&mut cmd, timeout, true)?;
    let stderr = String::from_utf8_lossy(&result.stderr);

    // Create report.
    let mut report = CrashReport::new();
    report.executable_path = argv[0].to_string();
    if argv.len() > 1
        && let Some(fname) = Path::new(argv[0]).file_name()
    {
        let fname = fname.to_string_lossy();
        if fname.starts_with("lua") && !fname.ends_with(".lua") && argv[1].ends_with(".lua") {
            report.executable_path = argv[1].to_string();
        }
    }

    report.proc_cmdline = argv.join(" ");
    let _ = report.add_os_info();
    let _ = report.add_proc_environ();

    // Extract lua exception
    let Some(exception) = LuaException::new(&stderr) else {
        bail!("Lua exception is not found!");
    };

    // Parse exception
    report.lua_report = exception.lua_report();
    report.stacktrace = exception.extract_stacktrace()?;
    report.execution_class = exception.severity()?;
    if let Ok(crashline) = exception.crash_line() {
        report.crashline = crashline.to_string();
        if let CrashLine::Source(debug) = crashline
            && let Some(sources) = CrashReport::sources(&debug)
        {
            report.source = sources;
        }
    }
    let stacktrace = exception.parse_stacktrace()?;
    if let Some(path) = matches.get_one::<String>("strip-path") {
        util::strip_paths(&mut report, &stacktrace, path);
    }

    //Output report
    util::output_report(&report, &matches, &argv)
}
