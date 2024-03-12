use casr::triage::{fuzzing_crash_triage_pipeline, CrashInfo};
use casr::util;

use anyhow::bail;
use anyhow::Result;
use clap::{
    error::{ContextKind, ContextValue, ErrorKind},
    Arg, ArgAction,
};
use log::error;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

fn main() -> Result<()> {
    let matches = clap::Command::new("casr-afl")
        .version(clap::crate_version!())
        .about("Triage crashes found by AFL++ (Sharpfuzz)")
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
                .help("Timeout (in seconds) for target execution, 0 value means that timeout is disabled")
                .value_parser(clap::value_parser!(u64).range(0..))
        )
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .action(ArgAction::Set)
                .value_name("INPUT_DIR")
                .required(true)
                .help("AFL++ work directory")
                .value_parser(move |arg: &str| {
                    let i_dir = Path::new(arg);
                    if !i_dir.exists() {
                        let mut err = clap::Error::new(ErrorKind::ValueValidation);
                        err.insert(ContextKind::InvalidValue, ContextValue::String("Input directory doesn't exist.".to_owned()));
                        return Err(err);
                    }
                    if !i_dir.is_dir() {
                        let mut err = clap::Error::new(ErrorKind::ValueValidation);
                        err.insert(ContextKind::InvalidValue, ContextValue::String("Input path should be an AFL++ work directory.".to_owned()));
                        return Err(err);
                    }
                    Ok(i_dir.to_path_buf())
                })
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .action(ArgAction::Set)
                .required(true)
                .value_name("OUTPUT_DIR")
                .value_parser(clap::value_parser!(PathBuf))
                .help("Output directory with triaged reports")
        )
        .arg(
            Arg::new("force-remove")
                .short('f')
                .long("force-remove")
                .action(ArgAction::SetTrue)
                .help("Remove output project directory if it exists")
        )
        .arg(
            Arg::new("ignore-cmdline")
                .action(ArgAction::SetTrue)
                .long("ignore-cmdline")
                .help("Force <casr-gdb-args> usage to run target instead of searching for cmdline files in AFL fuzzing directory")
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
                .num_args(1..)
                .help("Add \"--casr-gdb-args \'./gdb_fuzz_target <arguments>\'\" to generate additional crash reports with casr-gdb (e.g., test whether program crashes without sanitizers)"),
        )
        .arg(
            Arg::new("ARGS")
                .action(ArgAction::Set)
                .num_args(1..)
                .last(true)
                .help("Add \"-- fuzz_target <arguments>\""),
        )
        .get_matches();

    // Init log.
    util::initialize_logging(&matches);

    // Get fuzz target args.
    let argv: Vec<&str> = if let Some(argvs) = matches.get_many::<String>("ARGS") {
        argvs.map(|v| v.as_str()).collect()
    } else {
        Vec::new()
    };

    // Get gdb args.
    let mut gdb_args = if let Some(argv) = matches.get_many::<String>("casr-gdb-args") {
        argv.cloned().collect()
    } else {
        Vec::new()
    };
    if gdb_args.is_empty() && matches.get_flag("ignore-cmdline") {
        bail!("casr-gdb-args is empty, but \"ignore-cmdline\" option is provided.");
    }

    // Get tool.
    let tool = if !argv.is_empty() && (argv[0].ends_with("dotnet") || argv[0].ends_with("mono")) {
        "casr-csharp"
    } else {
        "casr-gdb"
    };
    let tool_path = util::get_path(tool)?;

    if !gdb_args.is_empty() && tool != "casr-gdb" {
        bail!("casr-gdb-args is provided with other tool (casr-csharp).");
    }

    // Get input file argument index.
    let at_index = if gdb_args.is_empty() {
        argv.iter()
            .skip(1)
            .position(|s| s.contains("@@"))
            .map(|x| x + 1)
    } else {
        gdb_args
            .iter()
            .skip(1)
            .position(|s| s.contains("@@"))
            .map(|x| x + 1)
    };

    // Get all crashes.
    let mut crashes: HashMap<String, CrashInfo> = HashMap::new();
    for node_dir in fs::read_dir(matches.get_one::<PathBuf>("input").unwrap())? {
        let path = node_dir?.path();
        if !path.is_dir() {
            continue;
        }

        // Get crashes from one node.
        let mut crash_info = if !gdb_args.is_empty() {
            CrashInfo {
                target_args: if matches.get_flag("ignore-cmdline") {
                    gdb_args.clone()
                } else {
                    let cmdline_path = path.join("cmdline");
                    if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
                        cmdline.split_whitespace().map(|s| s.to_string()).collect()
                    } else {
                        error!("Couldn't read {}.", cmdline_path.display());
                        continue;
                    }
                },
                envs: HashMap::new(),
                ..Default::default()
            }
        } else {
            CrashInfo {
                target_args: argv.iter().map(|x| x.to_string()).collect(),
                envs: vec![
                    ("AFL_SKIP_BIN_CHECK".to_string(), "1".to_string()),
                    (
                        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES".to_string(),
                        "1".to_string(),
                    ),
                ]
                .into_iter()
                .collect(),
                at_index,
                ..Default::default()
            }
        };
        crash_info.casr_tool = tool_path.clone();

        // When we triage crashes for binaries, use casr-san.
        if !gdb_args.is_empty() {
            crash_info.at_index = crash_info
                .target_args
                .iter()
                .skip(1)
                .position(|s| s.contains("@@"))
                .map(|x| x + 1);

            if let Some(target) = crash_info.target_args.first() {
                match util::symbols_list(Path::new(target)) {
                    Ok(list) => {
                        if list.contains("__asan") {
                            crash_info.casr_tool = util::get_path("casr-san")?.clone();
                        }
                    }
                    Err(e) => {
                        error!("{e}");
                        continue;
                    }
                }
            } else {
                error!("Cmdline is empty. Path: {:?}", path.join("cmdline"));
                continue;
            }
        }

        // Push crash paths.
        for crash in path
            .read_dir()?
            .flatten()
            .filter(|e| e.file_name().into_string().unwrap().starts_with("crashes"))
            .flat_map(|e| e.path().read_dir())
            .flatten()
            .flatten()
            .filter(|e| e.file_name().into_string().unwrap().starts_with("id"))
        {
            let mut info = crash_info.clone();
            info.path = crash.path();
            crashes.insert(crash.file_name().into_string().unwrap(), info);
        }
    }

    if matches.get_flag("ignore-cmdline") {
        gdb_args = Vec::new();
    }

    // Generate reports
    fuzzing_crash_triage_pipeline(&matches, &crashes, &gdb_args)
}
