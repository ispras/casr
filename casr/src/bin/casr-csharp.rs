use casr::util;
use libcasr::{
    csharp::*, exception::Exception, init_ignored_frames, report::CrashReport, stacktrace::*,
};

use anyhow::{Result, bail};
use clap::{Arg, ArgAction, ArgGroup};
use regex::Regex;
use std::path::PathBuf;
use std::process::Command;

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

    init_ignored_frames!("csharp", "cpp");
    if let Some(path) = matches.get_one::<PathBuf>("ignore") {
        util::add_custom_ignored_frames(path)?;
    }
    // Get program args.
    let argv: Vec<&str> = if let Some(argvs) = matches.get_many::<String>("ARGS") {
        argvs.map(|s| s.as_str()).collect()
    } else {
        bail!("Wrong arguments for starting program");
    };

    // Check that args are valid.
    let Some(pos) = argv
        .iter()
        .position(|x| x.ends_with(".dll") || x.ends_with(".exe") || x.ends_with(".csproj"))
    else {
        bail!("dotnet/mono target is not specified by .dll, .exe or .csproj executable.");
    };

    // Get stdin for target program.
    let stdin_file = util::stdin_from_matches(&matches)?;

    // Get timeout.
    let timeout = *matches.get_one::<u64>("timeout").unwrap();

    // Run program.
    let mut csharp_cmd = Command::new(argv[0]);
    // Set ld preload
    if let Some(ld_preload) = util::get_ld_preload(&matches) {
        csharp_cmd.env("LD_PRELOAD", ld_preload);
    }
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
    // Set executable path (for C# .dll, .csproj (dotnet) or .exe (mono) file).
    report.executable_path = argv.get(pos).unwrap().to_string();
    report.proc_cmdline = argv.join(" ");
    let _ = report.add_os_info();
    let _ = report.add_proc_environ();

    // Get C# report.
    let csharp_stderr_list: Vec<String> =
        csharp_stderr.split('\n').map(|l| l.to_string()).collect();
    let re = Regex::new(r"^Unhandled [Ee]xception(?::\n|\. ).*").unwrap();
    if let Some(start) = csharp_stderr_list.iter().position(|x| re.is_match(x)) {
        let end = csharp_stderr_list[start..]
            .iter()
            .rposition(|x| !x.is_empty())
            .unwrap()
            + 1;
        report.csharp_report = csharp_stderr_list[start..end].to_vec();
        let report_str = report.csharp_report.join("\n");
        report.stacktrace = CSharpStacktrace::extract_stacktrace(&report_str)?;
        if let Some(exception) = CSharpException::parse_exception(&report_str) {
            report.execution_class = exception;
        }
    } else {
        // Call casr-san
        return util::call_casr_san(&matches, &argv, "casr-csharp");
    }

    let stacktrace = CSharpStacktrace::parse_stacktrace(&report.stacktrace)?;
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

    //Output report.
    util::output_report(&report, &matches, &argv)
}
