use casr::{common, util};
use libcasr::{
    init_ignored_frames, report::CrashReport, stacktrace::CrashLine, stacktrace::Filter,
    stacktrace::Stacktrace,
};

use anyhow::{Result, bail};
use clap::{Arg, ArgAction, ArgGroup};

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<()> {
    let matches = clap::Command::new("casr")
        .version(clap::crate_version!())
        .about("Create CASR reports (.casrep) from target output")
        .term_width(90)
        .arg(
            Arg::new("output")
                .long("output")
                .short('o')
                .global(true)
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .value_name("REPORT")
                .help(
                    "Path to save report. Path can be a directory, then report name is generated",
                ),
        )
        .arg(
            Arg::new("stdout")
                .long("stdout")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Print CASR report to stdout"),
        )
        .group(
            ArgGroup::new("out")
                .args(["stdout", "output"])
                //.required(true),
        )
        .arg(
            Arg::new("stdin")
                .long("stdin")
                .global(true)
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .value_name("FILE")
                .help("Stdin file for program"),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .short('t')
                .global(true)
                .action(ArgAction::Set)
                .default_value("0")
                .value_name("SECONDS")
                .help("Timeout (in seconds) for target execution, 0 value means that timeout is disabled")
                .value_parser(clap::value_parser!(u64))
        )
        .arg(
            Arg::new("ignore")
                .long("ignore")
                .global(true)
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .value_name("FILE")
                .help("File with regular expressions for functions and file paths that should be ignored"),
        )
        .arg(
            Arg::new("strip-path")
                .long("strip-path")
                .env("CASR_STRIP_PATH")
                .global(true)
                .action(ArgAction::Set)
                .value_name("PREFIX")
                .help("Path prefix to strip from stacktrace"),
        )
        .arg(
            Arg::new("ld-preload")
                .long("ld-preload")
                .env("CASR_PRELOAD")
                .global(true)
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
                //.required(true)
                .global(true)
                .help("Add \"-- <path> <arguments>\" to run"),
        )
        .subcommands([
            clap::Command::new("auto")
                .about("Auto define proper way to threat target output (default behavior)"),
            clap::Command::new("go")
                .about("Threat target output as Go reports"),
            clap::Command::new("lua")
                .about("Threat target output as Lua reports"),
            clap::Command::new("san")
                .about("Threat target output as AddressSanitizer or MemorySanitizer reports"),
            clap::Command::new("asan")
                .about("Threat target output as AddressSanitizer reports"),
            clap::Command::new("msan")
                .about("Threat target output as MemorySanitizer reports"),
        ])
        .get_matches();

    // TODO: manually validate required args: stdout/output, ARGS
    init_ignored_frames!("go", "lua", "rust", "san");

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

    // Get mode
    let mut mode = common::get_mode(&matches, &argv)?;

    // Prepare run
    common::prepare_run(&mode);

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
    // Update mode-dependent characteristics
    common::update_cmd(&mut cmd, &mode);
    // Get output
    let result = util::get_output(&mut cmd, timeout, true)?;
    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);

    // Create report
    let mut report = common::get_report_stub(&argv, &stdin_file, &mode);

    // Get report extractor
    let mut extractor = common::get_extracter(&stdout, &stderr, &mut mode)?;

    // Extract report
    common::fill_report(&mut report, extractor.report(), &mode);
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
        }
    }
    let stacktrace = extractor.parse_stacktrace()?;
    if let Some(path) = matches.get_one::<String>("strip-path") {
        util::strip_paths(&mut report, &stacktrace, path);
    }

    //Output report
    util::output_report(&report, &matches, &argv)
}
