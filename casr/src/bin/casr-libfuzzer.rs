use casr::triage::{fuzzing_crash_triage_pipeline, CrashInfo};
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
        .about("Triage crashes found by libFuzzer based fuzzer (C/C++/go-fuzz/Atheris/Jazzer/Jazzer.js/jsfuzz) or LibAFL based fuzzer")
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
                .value_parser(["auto", "gdb", "java", "js", "python", "san"])
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
    let mut argv: Vec<&str> = if let Some(argvs) = matches.get_many::<String>("ARGS") {
        argvs.map(|v| v.as_str()).collect()
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
    let hint = matches.get_one::<String>("hint").unwrap();

    // Get tool.
    let mut envs = HashMap::new();
    let tool = if hint == "python" || hint == "auto" && argv[0].ends_with(".py") {
        envs.insert("LD_PRELOAD".to_string(), util::get_atheris_lib()?);
        "casr-python"
    } else if hint == "java"
        || hint == "auto" && (argv[0].ends_with("jazzer") || argv[0].ends_with("java"))
    {
        "casr-java"
    } else if hint == "js"
        || hint == "auto"
            && (argv[0].ends_with(".js")
                || argv[0].ends_with("node")
                || argv.len() > 1 && argv[0].ends_with("npx") && argv[1] == "jazzer"
                || argv[0].ends_with("jsfuzz"))
    {
        "casr-js"
    } else if hint == "lua"
        || hint == "auto"
            && (argv[0].ends_with(".lua")
                || argv[0] == "lua"
                || argv[0] == "luajit"
                || argv.len() > 1 && argv[1].ends_with(".lua"))
    {
        "casr-lua"
    } else {
        let sym_list = util::symbols_list(Path::new(argv[0]))?;
        if hint == "san"
            || hint == "auto" && (sym_list.contains("__asan") || sym_list.contains("runtime.go"))
        {
            "casr-san"
        } else {
            "casr-gdb"
        }
    };
    let tool_path = util::get_path(tool)?;

    if !gdb_args.is_empty() && tool != "casr-gdb" && tool != "casr-san" {
        bail!("casr-gdb-args option is provided with incompatible tool. This option can be used with casr-san or casr-gdb.");
    }

    // Get input file argument index.
    let at_index = if let Some(idx) = argv.iter().skip(1).position(|s| s.contains("@@")) {
        idx + 1
    } else {
        argv.push("@@");
        argv.len() - 1
    };

    let crash_files: HashMap<String, PathBuf> = fs::read_dir(input_dir)?
        .flatten()
        .map(|p| p.path())
        .filter(|p| p.is_file())
        .map(|p| (p.file_name().unwrap().to_str().unwrap().to_string(), p))
        .collect();

    // Determine crash directory format for libfuzzer or LibAFL.
    let crash_filter = if crash_files
        .iter()
        .any(|(fname, _)| fname.starts_with("crash-") || fname.starts_with("leak-"))
    {
        |arg: &(&std::string::String, &PathBuf)| {
            arg.0.starts_with("crash-") || arg.0.starts_with("leak-")
        }
    } else {
        |arg: &(&std::string::String, &PathBuf)| !arg.0.starts_with(".")
    };

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
                    envs: envs.clone(),
                    at_index: Some(at_index),
                    casr_tool: tool_path.clone(),
                },
            )
        })
        .collect();

    // Generate reports
    fuzzing_crash_triage_pipeline(&matches, &crashes, &gdb_args)
}
