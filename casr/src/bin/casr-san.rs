extern crate anyhow;
extern crate clap;
extern crate gdb_command;
extern crate libcasr;
extern crate linux_personality;
extern crate regex;

use casr::util;
use libcasr::asan::{AsanContext, AsanStacktrace};
use libcasr::constants::*;
use libcasr::cpp::CppException;
use libcasr::exception::Exception;
use libcasr::execution_class::*;
use libcasr::gdb::*;
use libcasr::go::*;
use libcasr::init_ignored_frames;
use libcasr::report::CrashReport;
use libcasr::rust::RustPanic;
use libcasr::severity::Severity;
use libcasr::stacktrace::*;

use anyhow::{bail, Context, Result};
use clap::{App, Arg, ArgGroup};
use gdb_command::mappings::{MappedFiles, MappedFilesExt};
use gdb_command::stacktrace::StacktraceExt;
use gdb_command::*;
use linux_personality::personality;
use regex::Regex;

use std::env;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::Command;

fn main() -> Result<()> {
    let matches = App::new("casr-san")
        .version("2.5.1")
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

    init_ignored_frames!("cpp", "rust", "go");

    if let Some(path) = matches.value_of("ignore") {
        util::add_custom_ignored_frames(Path::new(path))?;
    }
    // Get stdin for target program.
    let stdin_file = util::stdin_from_matches(&matches)?;

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
    if sanitizers_stderr.contains("AddressSanitizer: out-of-memory") {
        bail!("Out of memory");
    }

    // Create report.
    let mut report = CrashReport::new();
    report.executable_path = argv[0].to_string();
    report.proc_cmdline = argv.join(" ");
    let _ = report.add_os_info();
    let _ = report.add_proc_environ();
    if let Some(mut file_path) = stdin_file.clone() {
        file_path = file_path.canonicalize().unwrap_or(file_path);
        report.stdin = file_path.display().to_string();
    }

    // If it is possible to extract Go stacktrace, it is Go.
    let stacktrace: Stacktrace;
    if let Ok(raw_stacktrace) = GoStacktrace::extract_stacktrace(&sanitizers_stderr) {
        report.stacktrace = raw_stacktrace;
        stacktrace = GoStacktrace::parse_stacktrace(&report.stacktrace)?;
        report.go_report = sanitizers_stderr
            .split('\n')
            .map(|l| l.trim_end().to_string())
            .collect();
        if let Some(exception) = GoPanic::parse_exception(&sanitizers_stderr) {
            report.execution_class = exception;
        }
    } else {
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
            let context = AsanContext(report.asan_report.clone());
            report.execution_class = context.severity()?;
            report.stacktrace = AsanStacktrace::extract_stacktrace(&report.asan_report.join("\n"))?;
        } else {
            // Get termination signal.
            if let Some(signal) = sanitizers_result.status.signal() {
                // Get stack trace and mappings from gdb.
                match signal as u32 {
                    SIGINFO_SIGILL | SIGINFO_SIGSYS => {
                        report.execution_class = ExecutionClass::find("BadInstruction").unwrap();
                    }
                    SIGINFO_SIGTRAP => {
                        report.execution_class = ExecutionClass::find("TrapSignal").unwrap();
                    }
                    SIGINFO_SIGABRT => {
                        report.execution_class = ExecutionClass::find("AbortSignal").unwrap();
                    }
                    SIGINFO_SIGBUS | SIGINFO_SIGSEGV => {
                        eprintln!("Segmentation fault occured, but there is not enough information availibale to determine \
                        exploitability. Try using casr-gdb instead.");
                        report.execution_class = ExecutionClass::find("AccessViolation").unwrap();
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

        // Get stacktrace to find crash line.
        stacktrace = if !report.asan_report.is_empty() {
            AsanStacktrace::parse_stacktrace(&report.stacktrace)?
        } else {
            let mut parsed_stacktrace = GdbStacktrace::parse_stacktrace(&report.stacktrace)?;
            if let Ok(mfiles) = MappedFiles::from_gdb(report.proc_maps.join("\n")) {
                parsed_stacktrace.compute_module_offsets(&mfiles);
            }
            parsed_stacktrace
        };
    }

    // Check for exceptions
    if let Some(class) = [CppException::parse_exception, RustPanic::parse_exception]
        .iter()
        .find_map(|parse| parse(&sanitizers_stderr))
    {
        report.execution_class = class;
    }

    // Get crash line.
    if let Ok(crash_line) = stacktrace.crash_line() {
        report.crashline = crash_line.to_string();
        if let CrashLine::Source(debug) = crash_line {
            if let Some(sources) = CrashReport::sources(&debug) {
                report.source = sources;
            }
        }
    }

    util::output_report(&report, &matches, &argv)
}
