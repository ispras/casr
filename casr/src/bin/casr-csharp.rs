use casr::util;
use libcasr::{
    csharp::*, exception::Exception, init_ignored_frames, java::*, report::CrashReport,
    stacktrace::*,
};

use anyhow::{bail, Result};
use clap::{Arg, ArgAction, ArgGroup};
use regex::Regex;
use std::path::PathBuf;
use std::process::Command;
use walkdir::WalkDir;

fn main() -> Result<()> {
    let matches = clap::Command::new("casr-csharp")
        .version(clap::crate_version!())
        .about("Create CASR reports (.casrep) from C# reports")
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
        // This is maybe not needed.
        .arg(
            Arg::new("source-dirs")
                .long("source-dirs")
                .env("CASR_SOURCE_DIRS")
                .action(ArgAction::Set)
                .num_args(1..)
                .value_delimiter(':')
                .value_parser(clap::value_parser!(PathBuf))
                .value_name("DIR")
                .help("Paths to directories with Java source files (list separated by ':' for env)"),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .action(ArgAction::Set)
                .default_value("0")
                .value_name("SECONDS")
                .help("Timeout (in seconds) for target execution, 0 value means that timeout is disabled")
                .value_parser(clap::value_parser!(u64).range(0..))
        )
        .arg(
            Arg::new("ignore")
                .long("ignore")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .value_name("FILE")
                .help("File with regular expressions for functions and file paths that should be ignored"),
        )
        // This is maybe not needed.
        .arg(
            Arg::new("strip-path")
                .long("strip-path")
                .env("CASR_STRIP_PATH")
                .action(ArgAction::Set)
                .value_name("PREFIX")
                .help("Path prefix to strip from stacktrace and crash line"),
        )
        // Maybe something else is needed to be added here.
        .arg(
            Arg::new("ARGS")
                .action(ArgAction::Set)
                .num_args(1..)
                .last(true)
                .help("Add \"-- <path> <arguments>\" to run"),
        )
        .get_matches();

    // Maybe here is not "csharp", but "cs".
    init_ignored_frames!("csharp", "cpp"); //TODO
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
    let mut csharp_cmd = Command::new(argv[0]);
    if let Some(ref file) = stdin_file {
        csharp_cmd.stdin(std::fs::File::open(file)?);
    }
    if argv.len() > 1 {
        csharp_cmd.args(&argv[1..]);
    }
    let csharp_result = util::get_output(&mut csharp_cmd, timeout, true)?;

    let csharp_stderr = String::from_utf8_lossy(&csharp_result.stderr);

    // Create report.
    let mut report = CrashReport::new();
    //
    // Here is the special code for csharp that creates report.
    //
    report.proc_cmdline = argv.join(" ");
    let _ = report.add_os_info();
    let _ = report.add_proc_environ();

    // Get C# report.
    let csharp_stderr_list: Vec<String> =
        csharp_stderr.split('\n').map(|l| l.to_string()).collect();
    let re = Regex::new(r"Exception in thread .*? |== Java Exception: ").unwrap();
    //
    // Here is the special regex for csharp.
    //
    if let Some(start) = csharp_stderr_list.iter().position(|x| re.is_match(x)) {
        report.csharp_report = csharp_stderr_list[start..].to_vec();
        //
        // Parsing of stderr list here.
        //
        let report_str = report.csharp_report.join("\n");
        report.stacktrace = CSharpStacktrace::extract_stacktrace(&report_str)?;
        if let Some(exception) = CSharpException::parse_exception(&report_str) {
            report.execution_class = exception;
        }
    } else {
        // Call error here maybe.
    }

    let stacktrace = CSharpStacktrace::parse_stacktrace(&report.stacktrace)?;
    if let Ok(crash_line) = stacktrace.crash_line() {
        report.crashline = crash_line.to_string();
        if let CrashLine::Source(debug) = crash_line {
            //
            // Maybe other code is here.
            //
            if let Some(sources) = CrashReport::sources(&debug) {
                report.source = sources;
            }
        }
    }

    //
    // Something else is here maybe.
    //

    //Output report
    util::output_report(&report, &matches, &argv)
}
