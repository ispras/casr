use casr::util;
use libcasr::constants::*;
use libcasr::exception::Exception;
use libcasr::init_ignored_frames;
use libcasr::java::*;
use libcasr::report::CrashReport;
use libcasr::stacktrace::*;

use anyhow::{bail, Context, Result};
use clap::{Arg, ArgAction, ArgGroup};
use regex::Regex;
use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<()> {
    let matches = clap::Command::new("casr-java")
        .version(clap::crate_version!())
        .about("Create CASR reports (.casrep) from java reports")
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
            Arg::new("ARGS")
                .action(ArgAction::Set)
                .num_args(1..)
                .last(true)
                .help("Add \"-- <path> <arguments>\" to run"),
        )
        .get_matches();

    init_ignored_frames!("java"); //TODO
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
    let mut java_cmd = Command::new(argv[0]);
    if let Some(ref file) = stdin_file {
        java_cmd.stdin(std::fs::File::open(file)?);
    }
    if argv.len() > 1 {
        java_cmd.args(&argv[1..]);
    }
    let java_result = java_cmd
        .output()
        .with_context(|| "Couldn't run target program")?;

    let java_stderr = String::from_utf8_lossy(&java_result.stderr);

    // Create report.
    let mut report = CrashReport::new();
    // Set executable path (java class path)
    if let Some(pos) = argv.iter().position(|x| {
        x.starts_with("-cp")
            || x.starts_with("--cp")
            || x.starts_with("-class-path")
            || x.starts_with("--classpath")
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
    report.proc_cmdline = argv.join(" ");
    let _ = report.add_os_info();
    let _ = report.add_proc_environ();

    // Get java report.
    let java_stderr_list: Vec<String> = java_stderr.split('\n').map(|l| l.to_string()).collect();
    let re = Regex::new(r"Exception in thread .*? |== Java Exception: ").unwrap();
    if let Some(start) = java_stderr_list.iter().position(|x| re.is_match(x)) {
        report.java_report = java_stderr_list[start..].to_vec();
        if let Some(end) = report
            .java_report
            .iter()
            .rposition(|x| x.starts_with("== libFuzzer crashing input =="))
        {
            report.java_report.drain(end..);
        }
        report.stacktrace = JavaStacktrace::extract_stacktrace(&report.java_report.join("\n"))?;
        if let Some(exception) = JavaException::parse_exception(
            &report
                .java_report
                .iter()
                .rev()
                .cloned()
                .map(|mut x| {
                    x.push('\n');
                    x
                })
                .collect::<String>(),
        ) {
            report.execution_class = exception;
        }
    } else {
        // Call casr-san
        return util::call_casr_san(&matches, &argv, "casr-java");
    }

    if let Ok(crash_line) = JavaStacktrace::parse_stacktrace(&report.stacktrace)?.crash_line() {
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
