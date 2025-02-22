use casr::util;
use libcasr::{
    exception::Exception, init_ignored_frames, java::*, report::CrashReport, stacktrace::*,
};

use anyhow::{Result, bail};
use clap::{Arg, ArgAction, ArgGroup};
use regex::Regex;
use std::path::PathBuf;
use std::process::Command;
use walkdir::WalkDir;

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
                .help("Path prefix to strip from stacktrace and crash line"),
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

    init_ignored_frames!("java", "cpp"); //TODO
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
    let mut java_cmd = Command::new(argv[0]);
    if let Some(ref file) = stdin_file {
        java_cmd.stdin(std::fs::File::open(file)?);
    }
    if argv.len() > 1 {
        java_cmd.args(&argv[1..]);
    }
    let java_result = util::get_output(&mut java_cmd, timeout, true)?;

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
        report.java_report.retain(|x| !x.is_empty());
        let report_str = report.java_report.join("\n");
        report.stacktrace = JavaStacktrace::extract_stacktrace(&report_str)?;
        if let Some(exception) = JavaException::parse_exception(&report_str) {
            report.execution_class = exception;
        }
    } else {
        // Call casr-san
        return util::call_casr_san(&matches, &argv, "casr-java");
    }
    let stacktrace = JavaStacktrace::parse_stacktrace(&report.stacktrace)?;
    if let Ok(crash_line) = stacktrace.crash_line() {
        report.crashline = crash_line.to_string();
        if let CrashLine::Source(mut debug) = crash_line {
            // Modify DebugInfo to find sources
            let source_dirs = if let Some(sources) = matches.get_many::<PathBuf>("source-dirs") {
                sources.collect()
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

    if let Some(path) = matches.get_one::<String>("strip-path") {
        util::strip_paths(&mut report, &stacktrace, path);
    }

    //Output report
    util::output_report(&report, &matches, &argv)
}
