use casr::analysis::{generate_reports, CrashInfo};
use casr::util;

use anyhow::{bail, Result};
use clap::{
    error::{ContextKind, ContextValue, ErrorKind},
    Arg, ArgAction,
};

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

fn main() -> Result<()> {
    let matches = clap::Command::new("casr-libfuzzer")
        .version(clap::crate_version!())
        .about("Triage crashes found by libFuzzer based fuzzer (C/C++/go-fuzz/Atheris/Jazzer)")
        .term_width(90)
        .arg(
            Arg::new("log-level")
                .long("log-level")
                .short('l')
                .action(ArgAction::Set)
                .default_value("info")
                .value_parser(["info", "debug"])
                .help("Logging level")
        )
        .arg(Arg::new("jobs")
            .long("jobs")
            .short('j')
            .action(ArgAction::Set)
            .help("Number of parallel jobs for generating CASR reports [default: half of cpu cores]")
            .value_parser(clap::value_parser!(u32).range(1..)))
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .action(ArgAction::Set)
                .default_value("0")
                .value_name("SECONDS")
                .help("Timeout (in seconds) for target execution, disabled by default")
                .value_parser(clap::value_parser!(u64).range(0..))
        )
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .action(ArgAction::Set)
                .default_value(".")
                .value_name("INPUT_DIR")
                .help("Directory containing crashes found by libFuzzer")
                .value_parser(move |arg: &str| {
                    let i_dir = Path::new(arg);
                    if !i_dir.exists() {
                        let mut err = clap::Error::new(ErrorKind::ValueValidation);
                        err.insert(ContextKind::InvalidValue, ContextValue::String("Crash directory doesn't exist.".to_owned()));
                        return Err(err);
                    }
                    if !i_dir.is_dir() {
                        let mut err = clap::Error::new(ErrorKind::ValueValidation);
                        err.insert(ContextKind::InvalidValue, ContextValue::String("Input path should be a directory.".to_owned()));
                        return Err(err);
                    }
                    Ok(i_dir.to_owned())
                })
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .required(true)
                .value_name("OUTPUT_DIR")
                .help("Output directory with triaged reports")
        )
        .arg(
            Arg::new("no-cluster")
                .action(ArgAction::SetTrue)
                .long("no-cluster")
                .help("Do not cluster CASR reports")
        )
        .arg(Arg::new("san-force")
            .long("san-force")
            .action(ArgAction::SetTrue)
            .help("Force casr-san run without sanitizers symbols check"))
        .arg(
            Arg::new("casr-gdb-args")
                .long("casr-gdb-args")
                .action(ArgAction::Set)
                .help("Specify casr-gdb target arguments to add casr reports for uninstrumented binary"),
        )
        .arg(
            Arg::new("ARGS")
                .action(ArgAction::Set)
                .num_args(1..)
                .last(true)
                .help("Add \"-- ./fuzz_target <arguments>\""),
        )
        .get_matches();

    // Init log.
    util::initialize_logging(&matches);

    // Get input dir
    let input_dir = matches.get_one::<PathBuf>("input").unwrap().as_path();

    // Get fuzz target args.
    let argv: Vec<&str> = if let Some(argvs) = matches.get_many::<String>("ARGS") {
        argvs.map(|v| v.as_str()).collect()
    } else {
        bail!("Invalid fuzz target arguments");
    };
    let at_index = argv
        .iter()
        .skip(1)
        .position(|s| s.contains("@@"))
        .map(|x| x + 1);

    // Get all crashes.
    let crashes: HashMap<String, CrashInfo> = fs::read_dir(input_dir)?
        .flatten()
        .map(|p| p.path())
        .filter(|p| p.is_file())
        .map(|p| {
            (
                p.file_name().unwrap().to_str().unwrap().to_string(),
                CrashInfo {
                    path: p,
                    target_args: argv.iter().map(|x| x.to_string()).collect(),
                    at_index,
                    is_asan: true,
                },
            )
        })
        .filter(|(fname, _)| fname.starts_with("crash-") || fname.starts_with("leak-"))
        .collect();
    let tool = if argv[0].ends_with(".py") {
        "casr-python"
    } else if argv[0].ends_with("jazzer") || argv[0].ends_with("java") {
        "casr-java"
    } else {
        let sym_list = util::symbols_list(Path::new(argv[0]))?;
        if sym_list.contains("__asan")
            || sym_list.contains("runtime.go")
            || matches.get_flag("san-force")
        {
            "casr-san"
        } else {
            "casr-gdb"
        }
    };

    let gdb_argv = if let Some(argv) = matches.get_one::<String>("casr-gdb-args") {
        argv.split(' ')
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
    } else {
        Vec::new()
    };

    // Generate reports
    generate_reports(&matches, &crashes, tool, &gdb_argv)
}
