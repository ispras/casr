extern crate clap;

use casr::constants::*;
use casr::exception::Exception;
use casr::init_ignored_frames;
use casr::python::{PythonException, PythonStacktrace};
use casr::report::CrashReport;
use casr::stacktrace::*;
use casr::util;

use anyhow::{bail, Context, Result};
use clap::{App, Arg, ArgGroup, ArgMatches};
use regex::Regex;
use std::path::Path;
use std::process::{Command, Stdio};

/// Call casr-san with similar options
///
/// # Arguments
///
/// * `matches` - casr options
///
/// * `argv` - executable file options
fn call_casr_san(matches: &ArgMatches, argv: &[&str]) -> Result<()> {
    let mut python_cmd = Command::new("casr-san");
    if let Some(report_path) = matches.value_of("output") {
        python_cmd.args(["--output", report_path]);
    } else {
        python_cmd.args(["--stdout"]);
    }
    if let Some(path) = matches.value_of("stdin") {
        python_cmd.args(["--stdin", path]);
    }
    if let Some(path) = matches.value_of("ignore") {
        python_cmd.args(["--ignore", path]);
    }
    python_cmd.arg("--").args(argv);

    let output = python_cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .with_context(|| format!("Couldn't launch {python_cmd:?}"))?;

    if output.status.success() {
        Ok(())
    } else {
        bail!("casr-san error when calling from casr-python");
    }
}

fn main() -> Result<()> {
    let matches = App::new("casr-python")
        .version("2.4.0")
        .author("Andrey Fedotov <fedotoff@ispras.ru>, Alexey Vishnyakov <vishnya@ispras.ru>, Georgy Savidov <avgor46@ispras.ru>, Ilya Yegorov <Yegorov_Ilya@ispras.ru>")
        .about("Create CASR reports (.casrep) from python reports")
        .term_width(90)
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .takes_value(true)
                .value_names(&["REPORT"])
                .help(
                    "Path to save report. Path can be a directory, then report name is generated",
                ),
        )
        .arg(
            Arg::new("stdout")
                .long("stdout")
                .help("Print CASR report to stdout"),
        )
        .group(
            ArgGroup::new("out")
                .args(&["stdout", "output"])
                .required(true),
        )
        .arg(
            Arg::new("stdin")
                .long("stdin")
                .takes_value(true)
                .value_name("FILE")
                .help("Stdin file for program"),
        )
        .arg(
            Arg::new("ignore")
                .long("ignore")
                .takes_value(true)
                .value_name("FILE")
                .help("File with regular expressions for functions and file paths that should be ignored"),
        )
        .arg(
            Arg::new("ARGS")
                .multiple_values(true)
                .takes_value(true)
                .last(true)
                .help("Add \"-- <path> <arguments>\" to run"),
        )
        .get_matches();

    init_ignored_frames!("python");
    if let Some(path) = matches.value_of("ignore") {
        util::add_custom_ignored_frames(Path::new(path))?;
    }
    // Get program args.
    let argv: Vec<&str> = if let Some(args) = matches.values_of("ARGS") {
        args.collect()
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
            // Call casr-san
            return call_casr_san(&matches, &argv);
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
        return call_casr_san(&matches, &argv);
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
