use casr::util;
use libcasr::{
    exception::Exception,
    init_ignored_frames,
    python::{PythonException, PythonStacktrace},
    report::CrashReport,
    stacktrace::*,
};

use anyhow::{Result, bail};
use clap::{Arg, ArgAction, ArgGroup};
use regex::Regex;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() -> Result<()> {
    let matches = clap::Command::new("casr-python")
        .version(clap::crate_version!())
        .about("Create CASR reports (.casrep) from python reports")
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

    init_ignored_frames!("python", "cpp");
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
    let mut python_cmd = Command::new(argv[0]);
    // Set ld preload
    if let Some(ld_preload) = util::get_ld_preload(&matches) {
        python_cmd.env("LD_PRELOAD", ld_preload);
    }
    if let Some(ref file) = stdin_file {
        python_cmd.stdin(std::fs::File::open(file)?);
    }
    if argv.len() > 1 {
        python_cmd.args(&argv[1..]);
    }
    let python_result = util::get_output(&mut python_cmd, timeout, true)?;

    let python_stderr = String::from_utf8_lossy(&python_result.stderr);

    // Create report.
    let mut report = CrashReport::new();
    report.executable_path = argv[0].to_string();
    if argv.len() > 1 {
        if let Some(fname) = Path::new(argv[0]).file_name() {
            let fname = fname.to_string_lossy();
            if fname.starts_with("python") && !fname.ends_with(".py") && argv[1].ends_with(".py") {
                report.executable_path = argv[1].to_string();
            }
        }
    }
    report.proc_cmdline = argv.join(" ");
    let _ = report.add_os_info();
    let _ = report.add_proc_environ();

    // Get python report.
    let python_stderr_list: Vec<String> =
        python_stderr.split('\n').map(|l| l.to_string()).collect();

    let re = Regex::new(
        r"==\d+==\s*(ERROR: (LeakSanitizer|AddressSanitizer|libFuzzer)|WARNING: MemorySanitizer): ",
    )
    .unwrap();
    if python_stderr_list.iter().any(|line| re.is_match(line)) {
        let python_stdout = String::from_utf8_lossy(&python_result.stdout);
        let python_stdout_list: Vec<String> =
            python_stdout.split('\n').map(|l| l.to_string()).collect();

        if let Some(report_start) = python_stdout_list
            .iter()
            .position(|line| line.contains("Uncaught Python exception: "))
        {
            // Set python report in casr report.
            let Some(report_end) = python_stdout_list.iter().rposition(|s| !s.is_empty()) else {
                bail!("Corrupted output: can't find stdout end");
            };
            let report_end = report_end + 1;
            report.python_report = Vec::from(&python_stdout_list[report_start..report_end]);

            report.stacktrace =
                PythonStacktrace::extract_stacktrace(&report.python_report.join("\n"))?;
            // Get exception from python report.
            if report.python_report.len() > 1 {
                if let Some(exception) = PythonException::parse_exception(&report.python_report[1])
                {
                    report.execution_class = exception;
                }
            }
        } else {
            // Call casr-san
            return util::call_casr_san(&matches, &argv, "casr-python");
        }
    } else if let Some(report_start) = python_stderr_list
        .iter()
        .position(|line| line.contains("Traceback "))
    {
        // Set python report in casr report.
        let Some(report_end) = python_stderr_list.iter().rposition(|s| !s.is_empty()) else {
            bail!("Corrupted output: can't find stderr end");
        };
        let report_end = report_end + 1;
        report.python_report = Vec::from(&python_stderr_list[report_start..report_end]);

        report.stacktrace = PythonStacktrace::extract_stacktrace(&report.python_report.join("\n"))?;

        if let Some(exception) =
            PythonException::parse_exception(report.python_report.last().unwrap())
        {
            report.execution_class = exception;
        }
    } else {
        // Call casr-san
        return util::call_casr_san(&matches, &argv, "casr-python");
    }
    let stacktrace = PythonStacktrace::parse_stacktrace(&report.stacktrace)?;
    if let Ok(crash_line) = stacktrace.crash_line() {
        report.crashline = crash_line.to_string();
        if let CrashLine::Source(debug) = crash_line {
            if let Some(sources) = CrashReport::sources(&debug) {
                report.source = sources;
            }
        }
    }

    if let Some(path) = matches.get_one::<String>("strip-path") {
        util::strip_paths(&mut report, &stacktrace, path);
    }

    //Output report
    util::output_report(&report, &matches, &argv)
}
