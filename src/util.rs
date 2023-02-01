use crate::execution_class::ExecutionClass;
use crate::report::CrashReport;

use crate::stacktrace_constants::STACK_FRAME_FILEPATH_IGNORE_REGEXES;
use crate::stacktrace_constants::STACK_FRAME_FUNCTION_IGNORE_REGEXES;
use anyhow::{bail, Context, Result};
use clap::ArgMatches;
use regex::Regex;
use std::fs::OpenOptions;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

/// This macro merges all [&str] slices into single Vec<String>.
#[macro_export]
macro_rules! concatall {
    ( $( $x:expr ),* ) => {
        {
            [$($x,)*].concat().iter().map(|x| x.to_string()).collect::<Vec<String>>()
        }
    };
}

/// Extract C++ exception info or rust panic message from stderr
///
/// # Arguments
///
/// * `stderr_list` - lines of stderr
///
/// # Return value
///
/// Exception info as a `ExecutionClass` struct
pub fn exception_from_stderr(stderr_list: &[String]) -> Option<ExecutionClass> {
    // CPP exception check
    let rexception = Regex::new(r"terminate called after throwing an instance of (.+)").unwrap();
    if let Some(pos) = stderr_list
        .iter()
        .position(|line| rexception.is_match(line))
    {
        let instance = rexception
            .captures(&stderr_list[pos])
            .unwrap()
            .get(1)
            .unwrap()
            .as_str()
            .trim_start_matches('\'')
            .trim_end_matches('\'');
        let message = if let Some(element) = stderr_list.get(pos + 1) {
            let rwhat = Regex::new(r"what\(\): +(.+)").unwrap();
            if let Some(cap) = rwhat.captures(element) {
                cap.get(1).unwrap().as_str().trim()
            } else {
                ""
            }
        } else {
            ""
        };
        return Some(ExecutionClass::new((
            "NOT_EXPLOITABLE",
            instance,
            message,
            "",
        )));
    }
    // Rust panic check
    let rexception = Regex::new(r"thread '.+?' panicked at '(.+)?'").unwrap();
    if let Some(pos) = stderr_list
        .iter()
        .position(|line| rexception.is_match(line))
    {
        let message = rexception
            .captures(&stderr_list[pos])
            .unwrap()
            .get(1)
            .unwrap()
            .as_str();
        return Some(ExecutionClass::new((
            "NOT_EXPLOITABLE",
            "RustPanic",
            message,
            "",
        )));
    }
    None
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
        println!("{}\n", repstr);
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
