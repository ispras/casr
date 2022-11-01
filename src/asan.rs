use gdb_command::stacktrace::*;

use regex::Regex;

/// Extract stack trace object from asan stack trace string
///
/// # Arguments
///
/// * `entries` - stack trace as vector
///
/// # Return value
///
/// Stack trace as a `Stacktrace` struct
pub fn stacktrace_from_asan(entries: &[String]) -> gdb_command::error::Result<Stacktrace> {
    let mut stacktrace = Stacktrace::new();

    for entry in entries.iter() {
        let mut stentry = StacktraceEntry::default();

        let re = Regex::new(
            r"#[0-9]+ 0x([0-9a-f]+) in (.+) at (.+) module ([^ ]+)\+(0x[0-9a-f]+|<null>)",
        )
        .unwrap();

        if let Some(caps) = re.captures(entry.as_ref()) {
            // Get address
            let num = caps.get(1).unwrap().as_str();
            let addr = u64::from_str_radix(num, 16);
            if addr.is_err() {
                return Err(gdb_command::error::Error::StacktraceParse(format!(
                    "Couldn't parse address: {}",
                    num
                )));
            }
            stentry.address = addr.unwrap();

            // Get function name
            let name = caps.get(2).unwrap().as_str();
            if name != "<null>" {
                stentry.function = name.to_string();
            }

            // Get sources
            // file[:line[:column]]
            // TODO: path may contain :
            let sources = caps.get(3).unwrap().as_str();
            if sources != "<null>" {
                let source: Vec<&str> = sources.rsplitn(3, ':').collect();
                if source.iter().any(|x| x.is_empty()) {
                    return Err(gdb_command::error::Error::StacktraceParse(format!(
                        "Couldn't parse source file path, line, or column: {}",
                        sources
                    )));
                }
                // Get source file.
                stentry.debug.file = source.last().unwrap().trim().to_string();
                // Get source line (optional).
                if source.len() > 1 {
                    let num = source[source.len() - 2];
                    let line = num.parse::<u64>();
                    if line.is_err() {
                        return Err(gdb_command::error::Error::StacktraceParse(format!(
                            "Couldn't parse source line: {}",
                            num
                        )));
                    }
                    stentry.debug.line = line.unwrap();
                }
                // Get source column (optional).
                if source.len() == 3 {
                    let num = source[0];
                    let column = num.parse::<u64>();
                    if column.is_err() {
                        return Err(gdb_command::error::Error::StacktraceParse(format!(
                            "Couldn't parse source column: {}",
                            num
                        )));
                    }
                    stentry.debug.column = column.unwrap();
                }
            }

            // Get module
            let module = caps.get(4).unwrap().as_str();
            if module != "<null>" {
                stentry.module = module.to_string();
                let offset = caps.get(5).unwrap().as_str();
                if offset != "<null>" {
                    let num = u64::from_str_radix(&offset[2..], 16); // Is offset[2..] safe?
                    if num.is_err() {
                        return Err(gdb_command::error::Error::StacktraceParse(format!(
                            "Couldn't parse file offset: {}+{}",
                            module, offset
                        )));
                    }
                    stentry.offset = num.unwrap();
                }
            }
            stacktrace.push(stentry);
        } else {
            return Err(gdb_command::error::Error::StacktraceParse(format!(
                "Couldn't parse stack trace entry: {}",
                entry
            )));
        }
    }

    Ok(stacktrace)
}
