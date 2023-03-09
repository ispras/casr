use crate::report::CrashReport;
use crate::stacktrace::STACK_FRAME_FILEPATH_IGNORE_REGEXES;
use crate::stacktrace::STACK_FRAME_FUNCTION_IGNORE_REGEXES;

use anyhow::{bail, Context, Result};
use clap::ArgMatches;
use std::fs::OpenOptions;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

/// This macro updates variables used to remove trusted functions from stack trace
#[macro_export]
macro_rules! init_ignored_frames {
    ( $( $x:expr ),* ) => {
        {
            let (funcs, files): (Vec<_>, Vec<_>) = [$($x,)*].iter().map(|&x|
                match x {
                    "python" => (STACK_FRAME_FUNCTION_IGNORE_REGEXES_PYTHON, STACK_FRAME_FILEPATH_IGNORE_REGEXES_PYTHON),
                    "rust" => (STACK_FRAME_FUNCTION_IGNORE_REGEXES_RUST, STACK_FRAME_FILEPATH_IGNORE_REGEXES_RUST),
                    "cpp" => (STACK_FRAME_FUNCTION_IGNORE_REGEXES_CPP, STACK_FRAME_FILEPATH_IGNORE_REGEXES_CPP),
                    "go" => (STACK_FRAME_FUNCTION_IGNORE_REGEXES_GO, STACK_FRAME_FILEPATH_IGNORE_REGEXES_GO),
                    &_ => (["^[^.]$"].as_slice(), ["^[^.]$"].as_slice()),
                }
            ).unzip();
           *STACK_FRAME_FUNCTION_IGNORE_REGEXES.write().unwrap() = funcs.concat().iter().map(|x| x.to_string()).collect::<Vec<String>>();
           *STACK_FRAME_FILEPATH_IGNORE_REGEXES.write().unwrap() = files.concat().iter().map(|x| x.to_string()).collect::<Vec<String>>();
        }
    };
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

    if matches.is_present("stdout") {
        println!("{repstr}\n");
    }

    if matches.is_present("output") {
        let mut report_path = PathBuf::from(matches.value_of("output").unwrap());
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
/// * `matches` - command line argumnets
///
/// # Return value
///
/// Path to file with stdin
pub fn stdin_from_matches(matches: &ArgMatches) -> Result<Option<PathBuf>> {
    if let Some(path) = matches.value_of("stdin") {
        let file = PathBuf::from(path);
        if file.exists() {
            Ok(Some(file))
        } else {
            bail!("Stdin file not found: {}", file.display());
        }
    } else {
        Ok(None)
    }
}
