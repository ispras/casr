use gdb_command::stacktrace::*;

use std::io::{prelude::*, BufReader};

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
                    format!("    {:<6} {}", start + i + 1, l.trim_end())
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
