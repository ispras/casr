use casr::{
    mode::{DynMode, lua::LuaMode, python::PythonMode},
    triage::{CrashInfo, fuzzing_crash_triage_pipeline},
    util,
};

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use clap::{
    Arg, ArgAction,
    error::{ContextKind, ContextValue, ErrorKind},
};

fn main() -> Result<()> {
    let matches = clap::Command::new("casr-libfuzzer")
        .version(clap::crate_version!())
        .about("Triage crashes found by libFuzzer based fuzzer (C/C++/go-fuzz/Atheris/Jazzer/Jazzer.js/jsfuzz/luzer) or LibAFL based fuzzer")
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
                .help("Timeout (in seconds) for target execution, 0 means that timeout is disabled")
                .value_parser(clap::value_parser!(u64))
        )
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .action(ArgAction::Set)
                .default_value(".")
                .value_name("INPUT_DIR")
                .help("Directory containing crashes found by libFuzzer or LibAFL")
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
            Arg::new("join")
                .long("join")
                .env("CASR_PREV_CLUSTERS_DIR")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .value_name("PREV_CLUSTERS_DIR")
                .help("Use directory with previously triaged reports for new reports accumulation")
        )
        .arg(
            Arg::new("force-remove")
                .short('f')
                .long("force-remove")
                .action(ArgAction::SetTrue)
                .help("Remove output project directory if it exists")
        )
        .arg(
            Arg::new("no-cluster")
                .action(ArgAction::SetTrue)
                .long("no-cluster")
                .help("Do not cluster CASR reports")
        )
        .arg(
            Arg::new("casr-gdb-args")
                .long("casr-gdb-args")
                .action(ArgAction::Set)
                .help("Add \"--casr-gdb-args \'./gdb_fuzz_target <arguments>\'\" to generate additional crash reports with casr-gdb (e.g., test whether program crashes without sanitizers)"),
        )
        .arg(
            Arg::new("hint")
                .long("hint")
                .value_name("HINT")
                .action(ArgAction::Set)
                .default_value("auto")
                .value_parser(
                    ["auto", "go", "gdb", "java", "js", "python", "rust", "san", "asan", "msan"]
                )
                .help("Hint to force run casr-HINT tool to analyze crashes")
        )
        .arg(
            Arg::new("ARGS")
                .action(ArgAction::Set)
                .num_args(1..)
                .last(true)
                .required(true)
                .help("Add \"-- ./fuzz_target <arguments>\""),
        )
        .get_matches();

    // Init log.
    util::initialize_logging(&matches);

    // Get input dir
    let input_dir = matches.get_one::<PathBuf>("input").unwrap().as_path();

    // Get fuzz target args.
    let mut argv: Vec<String> = if let Some(argv) = matches.get_many::<String>("ARGS") {
        argv.map(|arg| arg.as_str().to_string()).collect()
    } else {
        bail!("Invalid fuzz target arguments");
    };

    // Get gdb args.
    let gdb_args = if let Some(argv) = matches.get_one::<String>("casr-gdb-args") {
        shell_words::split(argv)?
    } else {
        Vec::new()
    };

    // Get hint
    let hint = matches
        .get_one::<String>("hint")
        .as_ref()
        .map(|x| x.as_str());
    // Get mode
    let mode = DynMode::try_from((hint, &argv))?;

    if !gdb_args.is_empty() && !mode.is_gdb_compatible() {
        eprintln!(
            "casr-gdb-args option is provided with incompatible tool. This option can be used with Sanitizers or GDB."
        );
    }

    let crash_files: HashMap<String, PathBuf> = fs::read_dir(input_dir)?
        .flatten()
        .map(|p| p.path())
        .filter(|p| p.is_file())
        .map(|p| (p.file_name().unwrap().to_str().unwrap().to_string(), p))
        .collect();

    // Determine crash directory format for libfuzzer or LibAFL.
    let mut is_libafl_based = false;
    let crash_filter = if crash_files
        .iter()
        .any(|(fname, _)| fname.ends_with(".metadata"))
    {
        is_libafl_based = true;
        |arg: &(&std::string::String, &PathBuf)| !arg.0.starts_with(".")
    } else {
        |arg: &(&std::string::String, &PathBuf)| {
            arg.0.starts_with("crash-") || arg.0.starts_with("leak-")
        }
    };

    // Get input file argument index.
    let at_index = if let Some(idx) = argv.iter().skip(1).position(|s| s.contains("@@")) {
        Some(idx + 1)
    } else if is_libafl_based || mode.is_mode::<LuaMode>() {
        None
    } else {
        argv.push("@@".to_string());
        Some(argv.len() - 1)
    };

    // Modify env
    let mut envs = HashMap::new();
    // Set PRELOAD for Python
    if mode.is_mode::<PythonMode>() {
        // NOTE: https://doc.rust-lang.org/std/env/fn.var.html#errors
        if env::var("CASR_PRELOAD").is_err() {
            envs.insert("CASR_PRELOAD".to_string(), util::get_atheris_lib()?);
        }
    }
    if argv.iter().any(|x| x.eq("-detect_leaks=0")) {
        let asan_options = std::env::var("ASAN_OPTIONS").unwrap_or_default();
        envs.insert(
            "ASAN_OPTIONS".to_string(),
            if asan_options.is_empty() {
                "detect_leaks=0".to_string()
            } else {
                format!("{asan_options},detect_leaks=0",)
            },
        );
    }
    // Set env once
    unsafe {
        for (key, val) in envs {
            env::set_var(key, val);
        }
    }

    // Get all crashes.
    let crashes: HashMap<String, CrashInfo> = crash_files
        .iter()
        .filter(crash_filter)
        .map(|(fname, p)| {
            (
                fname.clone(),
                CrashInfo {
                    path: p.to_path_buf(),
                    target_args: argv.iter().map(|x| x.to_string()).collect(),
                    at_index,
                    mode: mode.clone(),
                },
            )
        })
        .collect();

    // Generate reports
    fuzzing_crash_triage_pipeline(&matches, &crashes, &gdb_args)
}
