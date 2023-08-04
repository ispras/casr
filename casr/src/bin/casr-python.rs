use casr::util;
use libcasr::constants::*;
use libcasr::exception::Exception;
use libcasr::init_ignored_frames;
use libcasr::python::{PythonException, PythonStacktrace};
use libcasr::report::CrashReport;
use libcasr::stacktrace::*;

use anyhow::{bail, Context, Result};
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
            Arg::new("ignore")
                .long("ignore")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .value_name("FILE")
                .help("File with regular expressions for functions and file paths that should be ignored"),
        )
        .arg(
            Arg::new("sub-tool")
                .long("sub-tool")
                .default_value("casr-san")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .value_name("BIN")
                .help(
                    "Path to sub tool bin for crash analyze that will be called in case main tool fails",
                ),
        )
        .arg(
            Arg::new("ARGS")
                .action(ArgAction::Set)
                .num_args(1..)
                .last(true)
                .help("Add \"-- <path> <arguments>\" to run"),
        )
        .get_matches();

    init_ignored_frames!("python");
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

    // Run program.
    let mut python_cmd = Command::new(argv[0]);
    if let Some(ref file) = stdin_file {
        python_cmd.stdin(std::fs::File::open(file)?);
    }
    if argv.len() > 1 {
        python_cmd.args(&argv[1..]);
    }
    let python_result = python_cmd
        .output()
        .with_context(|| "Couldn't run target program")?;

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

    let re = Regex::new(r"==\d+==\s*ERROR: (LeakSanitizer|AddressSanitizer|libFuzzer):").unwrap();
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
            // Call sub tool
            return util::call_sub_tool(&matches, &argv, "casr-python");
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
        // Call sub tool
        return util::call_sub_tool(&matches, &argv, "casr-python");
    }

    if let Ok(crash_line) = PythonStacktrace::parse_stacktrace(&report.stacktrace)?.crash_line() {
        report.crashline = crash_line.to_string();
        if let CrashLine::Source(debug) = crash_line {
            if let Some(sources) = CrashReport::sources(&debug) {
                report.source = sources;
            }
        }
    }

    //Output report
    util::output_report(&report, &matches, &argv)
}
