extern crate lazy_static;

use crate::error::*;
use regex::Regex;
use std::collections::HashSet;
use std::fmt;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::RwLock;

// Re-export types from gdb_command for convenient use from Casr library
/// Represents the information about stack trace.
pub type Stacktrace = gdb_command::stacktrace::Stacktrace;
/// Represents the debug information of one frame in stack trace.
pub type DebugInfo = gdb_command::stacktrace::DebugInfo;
/// Represents the information about one line of the stack trace.
pub type StacktraceEntry = gdb_command::stacktrace::StacktraceEntry;

lazy_static::lazy_static! {
    /// Regular expressions for functions to be ignored.
    pub static ref STACK_FRAME_FUNCTION_IGNORE_REGEXES: RwLock<Vec<String>> = RwLock::new(
        Vec::new());
    /// Regular expressions for file paths to be ignored.
    pub static ref STACK_FRAME_FILEPATH_IGNORE_REGEXES: RwLock<Vec<String>> = RwLock::new(
        Vec::new());
}

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

/// Information about line in sources which caused a crash.
pub enum CrashLine {
    /// Crash line from debug info: source:line:column.
    Source(DebugInfo),
    /// Crash line from binary module: binary module and offset.
    Module {
        /// Path to binary module.
        file: String,
        /// Offset in binary module.
        offset: u64,
    },
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
                write!(f, "{file}+{offset:#x}")
            }
        }
    }
}

/// Stack trace processing trait.
pub trait ParseStacktrace {
    /// Extract stack trace from stream.
    fn extract_stacktrace(stream: &str) -> Result<Vec<String>>;

    /// Transform stack trace strings into Stacktrace type.
    fn parse_stacktrace(entries: &[String]) -> Result<Stacktrace>;
}

/// Extract crash line from stack trace.
pub trait CrashLineExt {
    /// Get crash line from stack trace: source:line or binary+offset.
    fn crash_line(&self) -> Result<CrashLine>;
}

impl CrashLineExt for Stacktrace {
    fn crash_line(&self) -> Result<CrashLine> {
        let mut trace = self.clone();
        trace.filter();

        let Some(crash_entry) = trace.get(0) else {
            return Err(Error::Casr(
                "No stack trace entries after filtering".to_string(),
            ));
        };

        if !crash_entry.debug.file.is_empty() {
            return Ok(CrashLine::Source(crash_entry.debug.clone()));
        } else if !crash_entry.module.is_empty() && crash_entry.offset != 0 {
            return Ok(CrashLine::Module {
                file: crash_entry.module.clone(),
                offset: crash_entry.offset,
            });
        }

        Err(Error::Casr(
            "Couldn't collect crash line from stack trace".to_string(),
        ))
    }
}

/// Compute the similarity between 2 stack traces
///
/// # Arguments
///
/// * `first` - first stacktrace
///
/// * `second` - second stacktrace
///
/// # Return value
///
/// Similarity coefficient
pub fn similarity(first: &Stacktrace, second: &Stacktrace) -> f64 {
    // Initializing coefficients
    let a: f64 = 0.04;
    let r: f64 = 0.13;
    // Creating the similarity matrix according to the PDM algorithm
    let k: usize = first.len() + 1;
    let n: usize = second.len() + 1;
    let mut raw_matrix = vec![0 as f64; k * n];
    let mut simatrix: Vec<_> = raw_matrix.as_mut_slice().chunks_mut(k).collect();
    let simatrix = simatrix.as_mut_slice();

    for i in 1..n {
        for j in 1..k {
            let cost = if first[j - 1] == second[i - 1] {
                // Calculating addition
                (-(i.min(j) as f64 * a + i.abs_diff(j) as f64 * r)).exp()
            } else {
                0.0
            };

            // Choosing maximum of three neigbors
            simatrix[i][j] =
                simatrix[i][j - 1].max(simatrix[i - 1][j].max(simatrix[i - 1][j - 1] + cost));
        }
    }
    // Result normalization
    let sum: f64 = (1..(k).min(n)).fold(0.0, |acc, i| acc + (-a * i as f64).exp());

    simatrix[n - 1][k - 1] / sum
}

/// Deduplicate stack traces
///
/// # Arguments
///
/// * `stacktraces` - slice of `Stacktrace` structs
///
/// # Return value
///
/// An vector of the same length as `stacktraces`.
/// Vec\[i\] is false, if original stacktrace i is a duplicate of any element of `stacktraces`.
pub fn dedup_stacktraces(stacktraces: &[Stacktrace]) -> Vec<bool> {
    let mut traces = HashSet::new();
    stacktraces
        .iter()
        .map(|trace| traces.insert(trace))
        .collect()
}

/// Perform the clustering of stack traces
///
/// # Arguments
///
/// * `stacktraces` - slice of `Stacktrace` structs
///
/// # Return value
///
/// An vector of the same length as `stacktraces`.
/// Vec\[i\] is the flat cluster number to which original stacktrace i belongs.
pub fn cluster_stacktraces(stacktraces: &[Stacktrace]) -> Result<Vec<u32>> {
    let len = stacktraces.len();
    // Writing compressed distance matrix into Vector<String>
    let lines: Vec<String> = (0..len)
        .into_iter()
        .map(|i| {
            let mut tmp_str = String::new();
            for j in i + 1..len {
                tmp_str += format!(
                    "{0:.3} ",
                    1.0 - similarity(&stacktraces[i], &stacktraces[j])
                )
                .as_str();
            }
            tmp_str
        })
        .collect();

    let python_cluster_script =
        "import numpy as np;\
        from scipy.cluster.hierarchy import fcluster, linkage;\
        a = np.fromstring(input(), dtype=float, sep=' ');\
        print(*fcluster(linkage([a] if type(a.tolist()) is float else a, method=\"complete\"), 0.3, criterion=\"distance\"))";

    let Ok(mut python) = Command::new("python3")
        .args(["-c", python_cluster_script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn() else {
        return Err(Error::Casr("Failed to launch python3".to_string()));
    };
    {
        let python_stdin = python.stdin.as_mut().unwrap();
        if python_stdin.write_all(lines.join("").as_bytes()).is_err() {
            return Err(Error::Casr(
                "Error while writing to stdin of python script".to_string(),
            ));
        }
    }
    let python = python.wait_with_output()?;

    if !python.status.success() {
        return Err(Error::Casr(format!(
            "Failed to start python script. Error: {}",
            String::from_utf8_lossy(&python.stderr)
        )));
    }
    let output = String::from_utf8_lossy(&python.stdout);
    let clusters = output
        .split(' ')
        .filter_map(|x| x.trim().parse::<u32>().ok())
        .collect::<Vec<u32>>();

    if clusters.len() != len {
        return Err(Error::Casr(format!(
            "Number of casreps({}) differs from array length({}) from python",
            len,
            clusters.len()
        )));
    }

    Ok(clusters)
}

/// Stack trace filtering trait.
pub trait Filter {
    /// Filter frames from the stack trace that are not related to analyzed code containing crash.
    fn filter(&mut self);
}

impl Filter for Stacktrace {
    fn filter(&mut self) {
        // Compile function regexp.
        let rstring = STACK_FRAME_FUNCTION_IGNORE_REGEXES
            .read()
            .unwrap()
            .iter()
            .map(|s| format!("({s})|"))
            .collect::<String>();
        let rfunction = Regex::new(&rstring[0..rstring.len() - 1]).unwrap();

        // Compile file regexp.
        let rstring = STACK_FRAME_FILEPATH_IGNORE_REGEXES
            .read()
            .unwrap()
            .iter()
            .map(|s| format!("({s})|"))
            .collect::<String>();
        let rfile = Regex::new(&rstring[0..rstring.len() - 1]).unwrap();

        // For libfuzzer: delete functions below LLVMFuzzerTestOneInput
        if let Some(pos) = &self
            .iter()
            .position(|x| x.function.contains("LLVMFuzzerTestOneInput"))
        {
            self.drain(pos + 1..);
        }

        // Remove trusted functions from stack trace
        self.retain(|entry| {
            (entry.function.is_empty() || !rfunction.is_match(&entry.function))
                && (entry.module.is_empty() || !rfile.is_match(&entry.module))
                && (entry.debug.file.is_empty() || !rfile.is_match(&entry.debug.file))
        });
    }
}
