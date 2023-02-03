extern crate anyhow;
extern crate casr;
extern crate clap;
extern crate gdb_command;
extern crate linux_personality;
extern crate regex;

use casr::analysis::*;
use casr::concat_slices;
use casr::debug;
use casr::debug::CrashLine;
use casr::execution_class::*;
use casr::report::CrashReport;
use casr::stacktrace_constants::*;
use casr::util;

use anyhow::{bail, Context, Result};
use clap::{App, Arg, ArgGroup};
use gdb_command::*;
use linux_personality::personality;
use regex::Regex;
use std::env;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() -> Result<()> {
    let matches = App::new("casr-san")
        .version("2.4.0")
        .author("Andrey Fedotov <fedotoff@ispras.ru>, Alexey Vishnyakov <vishnya@ispras.ru>, Georgy Savidov <avgor46@ispras.ru>")
        .about("Create CASR reports (.casrep) from sanitizer reports")
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
                .help("Add \"-- ./binary <arguments>\" to run executable"),
        )
        .get_matches();

    // Get program args.
    let argv: Vec<&str> = if let Some(argvs) = matches.values_of("ARGS") {
        argvs.collect()
    } else {
        bail!("Wrong arguments for starting program");
    };

    *STACK_FRAME_FUNCTION_IGNORE_REGEXES.write().unwrap() = concat_slices!(
        STACK_FRAME_FUNCTION_IGNORE_REGEXES_RUST,
        STACK_FRAME_FUNCTION_IGNORE_REGEXES_CPP
    );
    *STACK_FRAME_FILEPATH_IGNORE_REGEXES.write().unwrap() = concat_slices!(
        STACK_FRAME_FILEPATH_IGNORE_REGEXES_RUST,
        STACK_FRAME_FILEPATH_IGNORE_REGEXES_CPP
    );

    if let Some(path) = matches.value_of("ignore") {
        util::add_custom_ignored_frames(Path::new(path))?;
    }
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
        std::env::set_var("ASAN_OPTIONS", asan_options);
    } else {
        std::env::set_var("ASAN_OPTIONS", "hard_rss_limit_mb=2048");
    }

    // Run program with sanitizers.
    let mut sanitizers_cmd = Command::new(argv[0]);
    if let Some(ref file) = stdin_file {
        sanitizers_cmd.stdin(std::fs::File::open(file).unwrap());
    }
    if argv.len() > 1 {
        sanitizers_cmd.args(&argv[1..]);
    }
    let sanitizers_result = unsafe {
        sanitizers_cmd
            .pre_exec(|| {
                if personality(linux_personality::ADDR_NO_RANDOMIZE).is_err() {
                    panic!("Cannot set personality");
                }
                Ok(())
            })
            .output()
            .with_context(|| "Couldn't run target program with sanitizers")?
    };
    let sanitizers_stderr = String::from_utf8_lossy(&sanitizers_result.stderr);

    if sanitizers_stderr.contains("Cannot set personality") {
        bail!("Cannot set personality (if you are running docker, use --privileged)");
    }

    // Detect OOMs.
    if sanitizers_stderr.contains("AddressSanitizer: hard rss limit exhausted") {
        bail!("Out of memory: hard_rss_limit_mb exhausted");
    }

    // Create report.
    let mut report = CrashReport::new();
    report.executable_path = argv[0].to_string();
    report.proc_cmdline = argv.join(" ");
    let _ = report.add_os_info();
    if let Some(mut file_path) = stdin_file.clone() {
        file_path = file_path.canonicalize().unwrap_or(file_path);
        report.stdin = file_path.display().to_string();
    }

    // Get ASAN report.
    let san_stderr_list: Vec<String> = sanitizers_stderr
        .split('\n')
        .map(|l| l.trim_end().to_string())
        .collect();
    let rasan_start =
        Regex::new(r"==\d+==\s*ERROR: (LeakSanitizer|AddressSanitizer|libFuzzer):").unwrap();
    if let Some(report_start) = san_stderr_list
        .iter()
        .position(|line| rasan_start.is_match(line))
    {
        // Set ASAN report in casr report.
        let report_end = san_stderr_list.iter().rposition(|s| !s.is_empty()).unwrap() + 1;
        report.asan_report = Vec::from(&san_stderr_list[report_start..report_end]);
        if report.asan_report[0].contains("LeakSanitizer") {
            report.execution_class = ExecutionClass::find("memory-leaks").unwrap().clone();
        } else {
            let summary = Regex::new(r"SUMMARY: *(AddressSanitizer|libFuzzer): (\S+)").unwrap();

            if let Some(caps) = report.asan_report.iter().find_map(|s| summary.captures(s)) {
                // Match Sanitizer.
                match caps.get(1).unwrap().as_str() {
                    "libFuzzer" => {
                        if let Ok(class) =
                            ExecutionClass::san_find(caps.get(2).unwrap().as_str(), None, false)
                        {
                            report.execution_class = class.clone();
                        }
                    }
                    _ => {
                        // AddressSanitizer
                        let san_type = caps.get(2).unwrap().as_str();
                        let mem_access = if let Some(second_line) = report.asan_report.get(1) {
                            let raccess = Regex::new(r"(READ|WRITE|ACCESS)").unwrap();
                            if let Some(access_type) = raccess.captures(second_line) {
                                Some(access_type.get(1).unwrap().as_str())
                            } else if let Some(third_line) = report.asan_report.get(2) {
                                raccess
                                    .captures(third_line)
                                    .map(|access_type| access_type.get(1).unwrap().as_str())
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        let rcrash_address = Regex::new("on.*address 0x([0-9a-f]+)").unwrap();
                        let near_null = if let Some(crash_address) =
                            rcrash_address.captures(&report.asan_report[0])
                        {
                            is_near_null(u64::from_str_radix(
                                crash_address.get(1).unwrap().as_str(),
                                16,
                            )?)
                        } else {
                            false
                        };
                        if let Ok(class) = ExecutionClass::san_find(san_type, mem_access, near_null)
                        {
                            report.execution_class = class.clone();
                        }
                    }
                }
            }
        }

        // Get stack trace from asan report.
        let first = report.asan_report.iter().position(|x| x.contains(" #0 "));
        if first.is_none() {
            bail!("Couldn't find stack trace in sanitizer's report");
        }

        // Stack trace is splitted by empty line.
        let first = first.unwrap();
        let last = report
            .asan_report
            .iter()
            .skip(first)
            .position(|val| val.is_empty());
        if last.is_none() {
            bail!("Couldn't find stack trace end in sanitizer's report");
        }
        let last = last.unwrap();
        report.stacktrace = report.asan_report[first..first + last]
            .iter()
            .map(|s| s.trim().to_string())
            .collect::<Vec<String>>();
    } else {
        // Get termination signal.
        if let Some(signal) = sanitizers_result.status.signal() {
            // Get stack trace and mappings from gdb.
            match signal as u32 {
                SIGINFO_SIGILL | SIGINFO_SIGSYS => {
                    report.execution_class =
                        ExecutionClass::find("BadInstruction").unwrap().clone();
                }
                SIGINFO_SIGTRAP => {
                    report.execution_class = ExecutionClass::find("TrapSignal").unwrap().clone();
                }
                SIGINFO_SIGABRT => {
                    report.execution_class = ExecutionClass::find("AbortSignal").unwrap().clone();
                }
                SIGINFO_SIGBUS | SIGINFO_SIGSEGV => {
                    eprintln!("Segmentation fault occured, but there is not enough information availibale to determine \
                    exploitability. Try using casr-gdb instead.");
                    report.execution_class =
                        ExecutionClass::find("AccessViolation").unwrap().clone();
                }
                _ => {
                    // "Undefined" is by default in report.
                }
            }

            // Get stack trace and mappings from gdb.
            let gdb_result = GdbCommand::new(&ExecType::Local(&argv))
                .stdin(&stdin_file)
                .r()
                .bt()
                .mappings()
                .launch()
                .with_context(|| "Unable to get results from gdb")?;

            let frame = Regex::new(r"^ *#[0-9]+").unwrap();
            report.stacktrace = gdb_result[0]
                .split('\n')
                .filter(|x| frame.is_match(x))
                .map(|x| x.to_string())
                .collect::<Vec<String>>();
            report.proc_maps = gdb_result[1]
                .split('\n')
                .skip(4)
                .map(|x| x.to_string())
                .collect::<Vec<String>>();
        } else {
            // Normal termination.
            bail!("Program terminated (no crash)");
        }
    }

    // Check for exceptions
    if let Some(class) = util::exception_from_stderr(&san_stderr_list) {
        report.execution_class = class;
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

    util::output_report(&report, &matches, &argv)
}
