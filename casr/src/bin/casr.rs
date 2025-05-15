use casr::{common, util};
use libcasr::{report::CrashReport, stacktrace::CrashLine};

use anyhow::{Result, bail};
use clap::{Arg, ArgAction, ArgGroup};

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<()> {
    let matches = clap::Command::new("casr")
        .version(clap::crate_version!())
        .about("Create CASR reports (.casrep) from target output")
        .term_width(90)
        .arg(
            Arg::new("output")
                .long("output")
                .short('o')
                .global(true)
                .group("out")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .value_name("REPORT")
                .help(
                    "Path to save report. Path can be a directory, then report name is generated",
                ),
        )
        .arg(
            Arg::new("stdout")
                .long("stdout")
                .global(true)
                .group("out")
                .action(ArgAction::SetTrue)
                .help("Print CASR report to stdout"),
        )
        .group(
            ArgGroup::new("out")
                .args(["stdout", "output"])
        )
        .arg(
            Arg::new("stdin")
                .long("stdin")
                .global(true)
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .value_name("FILE")
                .help("Stdin file for program"),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .short('t')
                .global(true)
                .action(ArgAction::Set)
                .default_value("0")
                .value_name("SECONDS")
                .help("Timeout (in seconds) for target execution, 0 value means that timeout is disabled")
                .value_parser(clap::value_parser!(u64))
        )
        .arg(
            Arg::new("ignore")
                .long("ignore")
                .global(true)
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .value_name("FILE")
                .help("File with regular expressions for functions and file paths that should be ignored"),
        )
        .arg(
            Arg::new("strip-path")
                .long("strip-path")
                .env("CASR_STRIP_PATH")
                .global(true)
                .action(ArgAction::Set)
                .value_name("PREFIX")
                .help("Path prefix to strip from stacktrace"),
        )
        .arg(
            Arg::new("ld-preload")
                .long("ld-preload")
                .env("CASR_PRELOAD")
                .global(true)
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
                .global(true)
                .help("Add \"-- <path> <arguments>\" to run"),
        )
        .subcommands([
            clap::Command::new("auto")
                .about("Auto define proper way to threat target output (default behavior)"),
            clap::Command::new("csharp")
                .about("Threat target output as C# reports"),
            clap::Command::new("go")
                .about("Threat target output as Go reports"),
            clap::Command::new("java")
                .about("Threat target output as Java reports")
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
                ),
            clap::Command::new("js")
                .about("Threat target output as JS reports"),
            clap::Command::new("lua")
                .about("Threat target output as Lua reports"),
            clap::Command::new("python")
                .about("Threat target output as Python or Atheris reports"),
            clap::Command::new("rust")
                .about("Threat target output as Rust reports"),
            clap::Command::new("san")
                .about("Threat target output as AddressSanitizer or MemorySanitizer reports"),
            clap::Command::new("asan")
                .about("Threat target output as AddressSanitizer reports"),
            clap::Command::new("msan")
                .about("Threat target output as MemorySanitizer reports"),
        ])
        .get_matches();

    // Check required args
    // NOTE: Combine `global` and `required` qualifiers is forbidden
    util::check_required(&matches, &["out", "ARGS"])?;

    if let Some(path) = matches.get_one::<PathBuf>("ignore") {
        util::add_custom_ignored_frames(path)?;
    }
    // Get program args.
    let mut argv: Vec<String> = if let Some(argv) = matches.get_many::<String>("ARGS") {
        argv.map(|arg| arg.as_str().to_string()).collect()
    } else {
        bail!("Wrong arguments for starting program");
    };

    // Get stdin for target program.
    let stdin = util::stdin_from_matches(&matches)?;

    // Get timeout
    let timeout = *matches.get_one::<u64>("timeout").unwrap();

    // Get mode
    let mut mode = common::get_mode(&matches, &argv)?;

    // Prepare run
    common::prepare_run(&mut argv, &mode)?;

    // Run program.
    let mut cmd = Command::new(&argv[0]);
    // Set ld preload
    if let Some(ld_preload) = util::get_ld_preload(&matches) {
        cmd.env("LD_PRELOAD", ld_preload);
    }
    if let Some(ref file) = stdin {
        cmd.stdin(std::fs::File::open(file)?);
    }
    if argv.len() > 1 {
        cmd.args(&argv[1..]);
    }
    // Update mode-dependent characteristics
    common::update_cmd(&mut cmd, &mode);
    // Get output
    let result = util::get_output(&mut cmd, timeout, true)?;
    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);

    // Create report
    let mut report = common::get_report_stub(&argv, &stdin, &mode)?;

    // Get report extractor
    let mut extractor = common::get_extractor(&stdout, &stderr, &mut mode)?;

    // Extract report
    common::fill_report(&mut report, extractor.report(), &mode);
    report.stacktrace = extractor.extract_stacktrace()?;
    if let Some(execution_class) = extractor.execution_class() {
        report.execution_class = execution_class;
    }
    if let Ok(crashline) = extractor.crash_line() {
        report.crashline = crashline.to_string();
        if let CrashLine::Source(debug) = crashline {
            if let Some(sources) = CrashReport::sources(&debug) {
                report.source = sources;
            }
            // Modify DebugInfo to find sources (for Java)
            common::update_sources(&mut report, debug, &matches, &mode);
        }
    }

    // Check for exceptions
    common::check_exeption(&mut report, &stderr, &mode);

    // Strip paths
    let stacktrace = extractor.parse_stacktrace()?;
    if let Some(path) = matches.get_one::<String>("strip-path") {
        util::strip_paths(&mut report, &stacktrace, path);
    }

    // Output report
    // TODO: rewrite func for &[String]
    let argv: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    util::output_report(&report, &matches, &argv)
}
