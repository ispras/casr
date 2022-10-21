use crate::execution_class::ExecutionClass;
use crate::report::CrashReport;

use anyhow::{bail, Context, Result};
use clap::ArgMatches;
use regex::Regex;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Extract C++ exception info from stderr
///
/// # Arguments
///
/// * `stderr_list` - lines of stderr
///
/// # Return value
///
/// Exception info as a `ExecutionClass` struct
pub fn cpp_exception_from_stderr(stderr_list: &[String]) -> Option<ExecutionClass> {
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
        Some(ExecutionClass::new((
            "NOT_EXPLOITABLE",
            instance,
            message,
            "",
        )))
    } else {
        None
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
