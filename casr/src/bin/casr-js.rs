use casr::util;
use libcasr::{
    exception::Exception, init_ignored_frames, js::*, report::CrashReport, stacktrace::*,
};

use anyhow::{Result, bail};
use clap::{Arg, ArgAction, ArgGroup};
use regex::Regex;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() -> Result<()> {
    let matches = clap::Command::new("casr-js")
        .version(clap::crate_version!())
        .about("Create CASR reports (.casrep) from JavaScript crash reports")
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
                .help("Path prefix to strip from stacktrace and crash line"),
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

    init_ignored_frames!("js", "cpp");
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
    let mut js_cmd = Command::new(argv[0]);
    // Set ld preload
    if let Some(ld_preload) = util::get_ld_preload(&matches) {
        js_cmd.env("LD_PRELOAD", ld_preload);
    }
    if let Some(ref file) = stdin_file {
        js_cmd.stdin(std::fs::File::open(file)?);
    }
    if argv.len() > 1 {
        js_cmd.args(&argv[1..]);
    }
    let js_result = util::get_output(&mut js_cmd, timeout, true)?;

    let js_stderr = String::from_utf8_lossy(&js_result.stderr);

    // Create report.
    let mut report = CrashReport::new();
    // Set executable path.
    report.executable_path = argv[0].to_string();
    let mut path_to_tool = PathBuf::new();
    path_to_tool.push(argv[0]);
    if argv.len() > 1 {
        let fpath = Path::new(argv[0]);
        if let Some(fname) = fpath.file_name() {
            path_to_tool = if fname == fpath.as_os_str() {
                let Ok(full_path_to_tool) = which::which(fname) else {
                    bail!("{} is not found in PATH", argv[0]);
                };
                full_path_to_tool
            } else {
                fpath.to_path_buf()
            };
            if !path_to_tool.exists() {
                bail!("Could not find the tool in the specified path {}", argv[0]);
            }
            let fname = fname.to_string_lossy();
            if (fname == "node" || fname == "jsfuzz") && argv[1].ends_with(".js") {
                report.executable_path = argv[1].to_string();
            } else if argv.len() > 2
                && fname == "npx"
                && argv[1] == "jazzer"
                && argv[2].ends_with(".js")
            {
                report.executable_path = argv[2].to_string();
            }
        }
    }
    report.proc_cmdline = argv.join(" ");
    let _ = report.add_os_info();
    let _ = report.add_proc_environ();

    // Get JS report.
    let js_stderr_list: Vec<String> = js_stderr.split('\n').map(|l| l.to_string()).collect();
    let re = Regex::new(r"^(?:.*Error:(?:\s+.*)?|Thrown at:)$").unwrap();
    if let Some(start) = js_stderr_list.iter().position(|x| re.is_match(x)) {
        report.js_report = js_stderr_list[start..].to_vec();
        report
            .js_report
            .retain(|x| !x.is_empty() && (x.trim().starts_with("at") || x.contains("Error:")));
        let report_str = report.js_report.join("\n");
        report.stacktrace = JsStacktrace::extract_stacktrace(&report_str)?;
        if let Some(exception) = JsException::parse_exception(&report.js_report[0]) {
            report.execution_class = exception;
        }
    } else {
        // Call casr-san with absolute path to interpreter/fuzzer
        let mut modified_argv = argv.clone();
        modified_argv[0] = path_to_tool.to_str().unwrap_or(argv[0]);
        return util::call_casr_san(&matches, &modified_argv, "casr-js");
    }
    let stacktrace = JsStacktrace::parse_stacktrace(&report.stacktrace)?;
    if let Ok(crash_line) = stacktrace.crash_line() {
        report.crashline = crash_line.to_string();
        if let CrashLine::Source(debug) = crash_line
            && let Some(sources) = CrashReport::sources(&debug)
        {
            report.source = sources;
        }
    }

    if let Some(path) = matches.get_one::<String>("strip-path") {
        util::strip_paths(&mut report, &stacktrace, path);
    }

    //Output report
    util::output_report(&report, &matches, &argv)
}
