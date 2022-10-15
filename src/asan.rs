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
pub fn stacktrace_from_asan(entries: &Vec<String>) -> gdb_command::error::Result<Stacktrace> {
    let mut stacktrace = Stacktrace::new();

    for entry in entries.iter() {
        let mut stentry = StacktraceEntry::default();

        // #10 0xdeadbeef
        let re = Regex::new(r"^ *#[0-9]+ +0x([0-9a-f]+) *").unwrap();
        let caps = re.captures(entry.as_ref());
        if caps.is_none() {
            return Err(gdb_command::error::Error::StacktraceParse(format!(
                "Couldn't parse frame and address in stack trace entry: {}",
                entry
            )));
        }
        let caps = caps.unwrap();

        // Get address.
        let num = caps.get(1).unwrap().as_str();
        let addr = u64::from_str_radix(num, 16);
        if addr.is_err() {
            return Err(gdb_command::error::Error::StacktraceParse(format!(
                "Couldn't parse address: {}",
                num
            )));
        }
        stentry.address = addr.unwrap();

        // Cut frame and address from string.
        let mut location = entry[caps.get(0).unwrap().as_str().len()..].trim();

        // Determine whether entry has function name.
        // TODO: there may be no function and source path may start with in and space.
        let has_function = location.starts_with("in ");

        // (module+0xdeadbeef)
        // TODO: (module)
        // We have to distinguish from (anonymous namespace) and function arguments.
        // TODO: module path may contain (.
        // We forbid ( in module path to distinguish from function arguments.
        // However, we allow ( when there is no function.
        // Regex::captures returns leftmost-first match, so, it won't match (BuildId: ).
        let re = if has_function {
            Regex::new(r"\(([^(]+)\+0x([0-9a-f]+)\)").unwrap()
        } else {
            Regex::new(r"\((.+)\+0x([0-9a-f]+)\)").unwrap()
        };
        if let Some(caps) = re.captures(location.as_ref()) {
            // Get module name.
            stentry.module = caps.get(1).unwrap().as_str().trim().to_string();
            // Get offset in module.
            let num = caps.get(2).unwrap().as_str();
            let off = u64::from_str_radix(num, 16);
            if off.is_err() {
                return Err(gdb_command::error::Error::StacktraceParse(format!(
                    "Couldn't parse module offset: {}",
                    num
                )));
            }
            stentry.offset = off.unwrap();
            // Cut module from string.
            location = location[..caps.get(0).unwrap().start()].trim();
        }

        // in function[(args)] [const] path
        // TODO: source file path may contain )
        if has_function {
            location = location[3..].trim();
            if location.is_empty() {
                return Err(gdb_command::error::Error::StacktraceParse(format!(
                    "Couldn't parse function name: {}",
                    entry
                )));
            }
            let i = if let Some(p) = location.rfind(')') {
                if location[p..].starts_with(") const ") {
                    p + 7
                } else {
                    p
                }
            } else {
                location.find(' ').unwrap_or(0)
            };
            let space_after_paren = location[i..].find(' ');
            if space_after_paren.is_none() {
                // Get function name.
                stentry.function = location.to_string();
                // No source path.
                stacktrace.push(stentry);
                continue;
            }
            let space_after_paren = space_after_paren.unwrap() + i;
            // Get function name.
            stentry.function = location[..space_after_paren].to_string();
            // Cut function name from string.
            location = location[space_after_paren..].trim();
        }

        // file[:line[:column]]
        // TODO: path may contain :
        if !location.is_empty() {
            let source: Vec<&str> = location.rsplitn(3, ':').collect();
            if source.iter().any(|x| x.is_empty()) {
                return Err(gdb_command::error::Error::StacktraceParse(format!(
                    "Couldn't parse source file path, line, or column: {}",
                    location
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

        stacktrace.push(stentry);
    }

    Ok(stacktrace)
}
