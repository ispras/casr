extern crate regex;

use crate::asan;
use crate::error;
use crate::error::Error;
use crate::report::CrashReport;
use crate::stacktrace_constants::*;

use gdb_command::mappings::*;
use gdb_command::stacktrace::*;
use regex::Regex;

use std::fmt;
use std::io::{prelude::*, BufReader};

pub enum CrashLine {
    // source:line:column.
    Source(DebugInfo),
    // Binary module and offset.
    Module { file: String, offset: u64 },
}

impl fmt::Display for CrashLine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            CrashLine::Source(debug) => {
                if debug.line != 0 && debug.column != 0 {
                    write!(f, "{}:{}:{}", debug.file, debug.line, debug.column)
                } else if debug.line != 0 {
                    write!(f, "{}:{}", debug.file, debug.line)
                } else {
                    write!(f, "{}", debug.file)
                }
            }
            CrashLine::Module { file, offset } => {
                write!(f, "{}+{:#x}", file, offset)
            }
        }
    }
}

/// Get crash line from stack trace: source:line or binary+offset.
///
/// # Arguments
///
/// * 'report' - crash report
pub fn crash_line(report: &CrashReport) -> error::Result<CrashLine> {
    let trace = if !report.asan_report.is_empty() {
        asan::stacktrace_from_asan(&report.stacktrace)?
    } else {
        // Get stack trace and update it from mappings.
        let mut gdbtrace = Stacktrace::from_gdb(&report.stacktrace.join("\n"))?;
        if let Ok(mfiles) = MappedFiles::from_gdb(&report.proc_maps.join("\n")) {
            gdbtrace.compute_module_offsets(&mfiles);
        }
        gdbtrace
    };

    // Compile function regexp.
    let rstring = STACK_FRAME_FUNCION_IGNORE_REGEXES
        .iter()
        .map(|s| format!("({})|", s))
        .collect::<String>();
    let rfunction = Regex::new(&rstring[0..rstring.len() - 1]).unwrap();

    // Compile file regexp.
    let rstring = STACK_FRAME_FILEPATH_IGNORE_REGEXES
        .iter()
        .map(|s| format!("({})|", s))
        .collect::<String>();
    let rfile = Regex::new(&rstring[0..rstring.len() - 1]).unwrap();

    let crash_entry = trace.iter().find(|entry| {
        (entry.function.is_empty() || !rfunction.is_match(&entry.function))
            && (entry.module.is_empty() || !rfile.is_match(&entry.module))
            && (entry.debug.file.is_empty() || !rfile.is_match(&entry.debug.file))
    });

    if let Some(crash_entry) = crash_entry {
        if !crash_entry.debug.file.is_empty() {
            return Ok(CrashLine::Source(crash_entry.debug.clone()));
        } else if !crash_entry.module.is_empty() && crash_entry.offset != 0 {
            return Ok(CrashLine::Module {
                file: crash_entry.module.clone(),
                offset: crash_entry.offset,
            });
        }

        return Err(Error::Casr(
            "Couldn't collect crash line from stack trace".to_string(),
        ));
    }

    Err(Error::Casr(
        "No stack trace entries after filtering".to_string(),
    ))
}

/// Get source code fragment for crash line
///
/// # Arguments
///
/// * 'debug' - debug information
pub fn sources(debug: &DebugInfo) -> Option<Vec<String>> {
    if debug.line == 0 {
        return None;
    }

    if let Ok(file) = std::fs::File::open(&debug.file) {
        let file = BufReader::new(file);
        let start: usize = if debug.line > 5 {
            debug.line as usize - 5
        } else {
            0
        };
        let mut lines: Vec<String> = file
            .lines()
            .skip(start)
            .enumerate()
            .take_while(|(i, _)| *i < 10)
            .map(|(i, l)| {
                if let Ok(l) = l {
                    format!("    {:<6} {}", start + i + 1, l)
                } else {
                    format!("    {:<6} Corrupted line", start + i + 1)
                }
            })
            .collect::<Vec<String>>();
        let crash_line = debug.line as usize - start - 1;
        if crash_line < lines.len() {
            lines[crash_line].replace_range(..4, "--->");
            return Some(lines);
        }
    }

    None
}
