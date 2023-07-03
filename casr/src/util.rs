//! Common utility functions.
extern crate libcasr;

use libcasr::report::CrashReport;
use libcasr::stacktrace::{
    STACK_FRAME_FILEPATH_IGNORE_REGEXES, STACK_FRAME_FUNCTION_IGNORE_REGEXES,
};

use anyhow::{bail, Context, Result};
use clap::ArgMatches;
use simplelog::*;
use std::fs::OpenOptions;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Call casr-san with the provided options
///
/// # Arguments
///
/// * `matches` - casr options
///
/// * `tool` - tool, that called casr-san
///
/// * `argv` - executable file options
pub fn call_casr_san(matches: &ArgMatches, argv: &[&str], tool: &str) -> Result<()> {
    let mut cmd = Command::new("casr-san");
    if let Some(report_path) = matches.get_one::<PathBuf>("output") {
        cmd.args(["--output", report_path.to_str().unwrap()]);
    } else {
        cmd.args(["--stdout"]);
    }
    if let Some(path) = matches.get_one::<PathBuf>("stdin") {
        cmd.args(["--stdin", path.to_str().unwrap()]);
    }
    if let Some(path) = matches.get_one::<String>("ignore") {
        cmd.args(["--ignore", path]);
    }
    cmd.arg("--").args(argv);

    let output = cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .with_context(|| format!("Couldn't launch {cmd:?}"))?;

    if output.status.success() {
        Ok(())
    } else {
        bail!("casr-san error when calling from {tool}");
    }
}

/// Save a report to the specified path
///
/// # Arguments
///
/// * `report` - output report
///
/// * `matches` - casr options
///
/// * `argv` - executable file options
pub fn output_report(report: &CrashReport, matches: &ArgMatches, argv: &[&str]) -> Result<()> {
    // Convert report to string.
    let repstr = serde_json::to_string_pretty(&report).unwrap();

    if matches.get_flag("stdout") {
        println!("{repstr}\n");
    }

    if let Some(report_path) = matches.get_one::<PathBuf>("output") {
        let mut report_path = report_path.clone();
        if report_path.is_dir() {
            let executable_name = PathBuf::from(&argv[0]);
            let file_name = match argv.iter().skip(1).find(|&x| Path::new(&x).exists()) {
                Some(x) => match Path::new(x).file_stem() {
                    Some(file) => file.to_os_string().into_string().unwrap(),
                    None => x.to_string(),
                },
                None => report.date.clone(),
            };
            report_path.push(format!(
                "{}_{}.casrep",
                executable_name
                    .as_path()
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap(),
                file_name
            ));
        }
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&report_path)
        {
            file.write_all(repstr.as_bytes()).with_context(|| {
                format!(
                    "Couldn't write data to report file `{}`",
                    report_path.display()
                )
            })?;
        } else {
            bail!("Couldn't save report to file: {}", report_path.display());
        }
    }
    Ok(())
}

/// Add custom regex for frames from user that should be ignored during analysis
///
/// # Arguments
///
/// * `path` - path to the specification file
pub fn add_custom_ignored_frames(path: &Path) -> Result<()> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Cannot open file: {}", path.display()))?;
    let mut reader = BufReader::new(file)
        .lines()
        .map(|x| x.unwrap())
        .collect::<Vec<String>>();
    if reader.is_empty() || !reader[0].contains("FUNCTIONS") && !reader[0].contains("FILES") {
        bail!(
            "File {} is empty or does not contain \
                    FUNCTIONS or FILES on the first line",
            path.display()
        );
    }
    let (funcs, paths) = if reader[0].contains("FUNCTIONS") {
        if let Some(bound) = reader.iter().position(|x| x.contains("FILES")) {
            let files = reader.split_off(bound);
            (reader, files)
        } else {
            (reader, vec![])
        }
    } else if let Some(bound) = reader.iter().position(|x| x.contains("FUNCTIONS")) {
        let funcs = reader.split_off(bound);
        (funcs, reader)
    } else {
        (vec![], reader)
    };
    STACK_FRAME_FUNCTION_IGNORE_REGEXES
        .write()
        .unwrap()
        .extend_from_slice(&funcs);
    STACK_FRAME_FILEPATH_IGNORE_REGEXES
        .write()
        .unwrap()
        .extend_from_slice(&paths);
    Ok(())
}

/// Check if stdin is set
///
/// # Arguments
///
/// * `matches` - command line arguments
///
/// # Return value
///
/// Path to file with stdin
pub fn stdin_from_matches(matches: &ArgMatches) -> Result<Option<PathBuf>> {
    if let Some(file) = matches.get_one::<PathBuf>("stdin") {
        if file.exists() {
            Ok(Some(file.to_owned()))
        } else {
            bail!("Stdin file not found: {}", file.display());
        }
    } else {
        Ok(None)
    }
}

/// Initialize logging with level from command line arguments (debug or info).
pub fn initialize_logging(matches: &ArgMatches) {
    let log_level = if matches.get_one::<String>("log-level").unwrap() == "debug" {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    let _ = TermLogger::init(
        log_level,
        ConfigBuilder::new()
            .set_time_offset_to_local()
            .unwrap()
            .build(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    );
}

/// Parse CASR report from file.
///
/// # Arguments
///
/// * `path` - path to CASR report.
pub fn report_from_file(path: &Path) -> Result<CrashReport> {
    let Ok(file) = std::fs::File::open(path) else {
        bail!("Error with opening Casr report: {}", path.display());
    };
    let report: Result<CrashReport, _> = serde_json::from_reader(BufReader::new(file));
    if let Err(e) = report {
        bail!("Error with parsing JSON {}: {}", path.display(), e);
    }
    Ok(report.unwrap())
}
