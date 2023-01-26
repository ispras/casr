extern crate clap;

use casr::debug;
use casr::debug::CrashLine;
use casr::error;
use casr::execution_class::*;
use casr::report::CrashReport;
use casr::util;

use anyhow::{bail, Context, Result};
use clap::{App, Arg, ArgGroup, ArgMatches};
use regex::Regex;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Get exception from python report.
///
/// # Arguments
///
/// * `exception_line` - python exception line
///
/// # Return value
///
/// ExecutionClass with python exception info
fn python_exception(exception_line: &str) -> error::Result<ExecutionClass> {
    let re = Regex::new(r#"([\w]+): (.+)"#).unwrap();
    if let Some(cap) = re.captures(exception_line) {
        Ok(ExecutionClass::new((
            "UNDEFINED",
            cap.get(1).unwrap().as_str(),
            cap.get(2).unwrap().as_str(),
            "",
        )))
    } else {
        Err(error::Error::Casr(format!(
            "Can't parse exception line: {}",
            exception_line
        )))
    }
}

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
        .with_context(|| format!("Couldn't launch {:?}", python_cmd))?;

    if output.status.success() {
        Ok(())
    } else {
        bail!("casr-san error when calling from casr-python");
    }
}

fn main() -> Result<()> {
    let matches = App::new("casr-python")
        .version("2.3.0")
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

    // Get program args.
    let argv: Vec<&str> = if let Some(args) = matches.values_of("ARGS") {
        args.collect()
    } else {
        bail!("Wrong arguments for starting program");
    };

    // Get stdin for target program.
    let stdin_file = if let Some(path) = matches.value_of("stdin") {
        let file = PathBuf::from(path);
        if file.exists() {
            Some(file)
        } else {
            bail!("Stdin file not found: {}", file.display());
        }
    } else {
        None
    };

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
            if let Some(report_end) = python_stdout_list.iter().rposition(|s| !s.is_empty()) {
                let report_end = report_end + 1;
                if report_end > python_stdout_list.len() {
                    bail!("Corrupted output: can't parse stdout end");
                }
                report.python_report = Vec::from(&python_stdout_list[report_start..report_end]);

                // Get exception from python report.
                if report.python_report.is_empty() {
                    bail!("Missing exception message");
                }
                if let Ok(exception) = python_exception(&report.python_report[1]) {
                    report.execution_class = exception;
                }

                // Get stack trace from python report.
                let first = report
                    .python_report
                    .iter()
                    .position(|line| line.starts_with("Traceback "));
                if first.is_none() {
                    bail!("Couldn't find traceback in python report");
                }

                // Stack trace is splitted by empty line.
                let first = first.unwrap();
                let last = report
                    .python_report
                    .iter()
                    .skip(first)
                    .rposition(|s| !s.is_empty());
                if last.is_none() {
                    bail!("Couldn't find traceback end in python report");
                }
                let last = last.unwrap();

                let re = Regex::new(
                    r#"(File ".+", line [\d]+, in .+|\[Previous line repeated (\d+) more times\])"#,
                )
                .unwrap();
                report.stacktrace = report.python_report[first..first + last]
                    .iter()
                    .rev()
                    .map(|s| s.trim().to_string())
                    .filter(|s| re.is_match(s))
                    .collect::<Vec<String>>();
            } else {
                bail!("Corrupted output: can't find stdout end");
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
        if let Some(report_end) = python_stderr_list.iter().rposition(|s| !s.is_empty()) {
            let report_end = report_end + 1;
            if report_end > python_stderr_list.len() {
                bail!("Corrupted output: can't parse stdout end");
            }
            report.python_report = Vec::from(&python_stderr_list[report_start..report_end]);

            let re = Regex::new(
                r#"(File ".+", line [\d]+, in .+|\[Previous line repeated (\d+) more times\])"#,
            )
            .unwrap();
            report.stacktrace = report
                .python_report
                .iter()
                .rev()
                .map(|s| s.trim().to_string())
                .filter(|s| re.is_match(s))
                .collect::<Vec<String>>();

            // Get exception from python report.
            let report_end = report_end - 1;
            if report.python_report.len() < report_end {
                bail!("Missing exception message");
            }
            if let Ok(exception) = python_exception(&report.python_report[report_end]) {
                report.execution_class = exception;
            }
        } else {
            bail!("Corrupted output: can't find stdout end");
        }
    } else {
        // Call casr-san
        return call_casr_san(&matches, &argv);
    }

    // Get crash line.
    if let Ok(crash_line) = debug::crash_line(&report) {
        report.crashline = crash_line.to_string();
        if let CrashLine::Source(debug) = crash_line {
            if let Some(sources) = debug::sources(&debug) {
                report.source = sources;
            }
        }
    }

    //Output report
    util::output_report(&report, &matches, &argv)
}
