//! Provides API's for parsing, filtering, deduplication and clustering.
extern crate kodama;
extern crate lazy_static;

use crate::constants::{
    STACK_FRAME_FILEPATH_IGNORE_REGEXES_CPP, STACK_FRAME_FILEPATH_IGNORE_REGEXES_CSHARP,
    STACK_FRAME_FILEPATH_IGNORE_REGEXES_GO, STACK_FRAME_FILEPATH_IGNORE_REGEXES_JAVA,
    STACK_FRAME_FILEPATH_IGNORE_REGEXES_JS, STACK_FRAME_FILEPATH_IGNORE_REGEXES_LUA,
    STACK_FRAME_FILEPATH_IGNORE_REGEXES_PYTHON, STACK_FRAME_FILEPATH_IGNORE_REGEXES_RUST,
    STACK_FRAME_FUNCTION_IGNORE_REGEXES_CPP, STACK_FRAME_FUNCTION_IGNORE_REGEXES_CSHARP,
    STACK_FRAME_FUNCTION_IGNORE_REGEXES_GO, STACK_FRAME_FUNCTION_IGNORE_REGEXES_JAVA,
    STACK_FRAME_FUNCTION_IGNORE_REGEXES_JS, STACK_FRAME_FUNCTION_IGNORE_REGEXES_LUA,
    STACK_FRAME_FUNCTION_IGNORE_REGEXES_PYTHON, STACK_FRAME_FUNCTION_IGNORE_REGEXES_RUST,
};

use crate::error::*;
use kodama::{Method, linkage};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Write};
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

/// Threshold for clusters diameter
pub const THRESHOLD: f64 = 0.3;

/// This macro updates variables used to remove trusted functions from stack trace
#[macro_export]
macro_rules! init_ignored_frames {
    ( $( $x:expr ),* ) => {
        {
            <Stacktrace as Filter>::init_frame_filter(&[$($x,)*]);
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

    /// Transform stack trace line into StacktraceEntry type.
    fn parse_stacktrace_entry(entry: &str) -> Result<StacktraceEntry>;

    /// Transform stack trace strings into Stacktrace type.
    fn parse_stacktrace(entries: &[String]) -> Result<Stacktrace> {
        entries
            .iter()
            .map(String::as_str)
            .map(Self::parse_stacktrace_entry)
            .collect()
    }
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

        let Some(crash_entry) = trace.first() else {
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
/// * `first` - first stack trace
///
/// * `second` - second stack trace
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

            // Choosing maximum of three neighbors
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
/// * `stacktraces` - slice of `Stacktrace` structures
///
/// # Return value
///
/// A vector of the same length as `stacktraces`.
/// Vec\[i\] is false, if original stacktrace i is a duplicate of any element of `stacktraces`.
pub fn dedup_stacktraces(stacktraces: &[Stacktrace]) -> Vec<bool> {
    let mut traces = HashSet::new();
    stacktraces
        .iter()
        .map(|trace| traces.insert(trace))
        .collect()
}

/// Perform the clustering by condensed dissimilarity matrix
///
/// # Arguments
///
/// * `matrix` - condensed dissimilarity matrix
///
/// * `len` - number of observations that are being clustered
///
/// # Return value
///
/// A vector of the `len` length.
/// Vec\[i\] is the flat cluster number to which original object i belongs.
pub fn cluster(mut matrix: Vec<f64>, len: usize) -> Result<Vec<usize>> {
    // Get hierarchical clustering binary tree
    let dendrogram = linkage(&mut matrix, len, Method::Complete);

    // Iterate through merging step until threshold is reached
    // at the beginning every node is in its own cluster
    let mut clusters = (0..len).map(|x| (x, vec![x])).collect::<HashMap<_, _>>();

    // Counter for new clusters, which are formed as unions of previous ones
    let mut counter = len;

    for step in dendrogram.steps() {
        // Break if threshold is reached
        if step.dissimilarity >= THRESHOLD {
            break;
        }

        // Combine nums from both clusters
        let mut nums = Vec::with_capacity(2);
        let mut cl = clusters.remove(&step.cluster1).unwrap();
        nums.append(&mut cl);
        let mut cl = clusters.remove(&step.cluster2).unwrap();
        nums.append(&mut cl);

        // Insert into hashmap and increase counter
        clusters.insert(counter, nums);
        counter += 1;
    }

    // Sort clusters by keys
    let mut clusters = clusters.into_iter().collect::<Vec<_>>();
    clusters.sort_by(|a, b| a.0.cmp(&b.0));

    // Flatten resulting clusters and reverse numbers
    let mut flat_clusters = vec![0; len];
    for (i, (_, nums)) in clusters.into_iter().enumerate() {
        for num in nums {
            // NOTE: Clusters enumerate from 1, not 0
            flat_clusters[num] = i + 1;
        }
    }

    Ok(flat_clusters)
}

/// Perform the clustering of stack traces
///
/// # Arguments
///
/// * `stacktraces` - slice of `Stacktrace` structures
///
/// # Return value
///
/// A vector of the same length as `stacktraces`.
/// Vec\[i\] is the flat cluster number to which original stack trace i belongs.
pub fn cluster_stacktraces(stacktraces: &[Stacktrace]) -> Result<Vec<usize>> {
    // Writing distance matrix
    // Only the values in the upper triangle are explicitly represented,
    // not including the diagonal
    let len = stacktraces.len();
    let mut condensed_dissimilarity_matrix = vec![];
    for i in 0..len {
        for j in i + 1..len {
            condensed_dissimilarity_matrix.push(1.0 - similarity(&stacktraces[i], &stacktraces[j]));
        }
    }
    cluster(condensed_dissimilarity_matrix, len)
}

/// Perform crashline deduplication for each cluster:
/// Reset Vec\[i\] to 0 if report crashline is duplicate of some other.
///
/// # Arguments
///
/// * `crashlines` - slice of crashlines as String
///
/// * 'clusters' - A vector of the same length as `crashlines`.
///   Vec\[i\] is the flat cluster number to which original casrep i belongs.
///
/// # Return value
///
/// Number of left casreps
pub fn dedup_crashlines(crashlines: &[String], clusters: &mut [usize]) -> usize {
    // Count number of clusters
    let cluster_num: usize = if !clusters.is_empty() {
        *clusters.iter().max().unwrap()
    } else {
        return 0;
    };
    // Init dedup crashline list for each cluster
    let mut unique_crashlines: Vec<HashSet<String>> = vec![HashSet::new(); cluster_num];

    // Init unique crashline counter, e.i. left casreps
    let mut unique_cnt = 0;
    // Dedup reports by crashline
    for (i, crashline) in crashlines.iter().enumerate() {
        // Leave report in the cluster if crashline is absent
        if crashline.is_empty() || unique_crashlines[clusters[i] - 1].insert(crashline.to_string())
        {
            unique_cnt += 1;
        } else {
            clusters[i] = 0;
        }
    }
    unique_cnt
}

/// Stack trace filtering trait.
pub trait Filter {
    /// Filter frames from the stack trace that are not related to analyzed code containing crash.
    fn filter(&mut self);

    /// Initialize global variables for stacktrace filtering
    ///
    /// # Arguments
    ///
    /// * `languages` - list of program languages for filtering
    fn init_frame_filter(languages: &[&str]) {
        let (funcs, files): (Vec<_>, Vec<_>) = languages
            .iter()
            .map(|&x| match x {
                "cpp" => (
                    STACK_FRAME_FUNCTION_IGNORE_REGEXES_CPP,
                    STACK_FRAME_FILEPATH_IGNORE_REGEXES_CPP,
                ),
                "csharp" => (
                    STACK_FRAME_FUNCTION_IGNORE_REGEXES_CSHARP,
                    STACK_FRAME_FILEPATH_IGNORE_REGEXES_CSHARP,
                ),
                "go" => (
                    STACK_FRAME_FUNCTION_IGNORE_REGEXES_GO,
                    STACK_FRAME_FILEPATH_IGNORE_REGEXES_GO,
                ),
                "java" => (
                    STACK_FRAME_FUNCTION_IGNORE_REGEXES_JAVA,
                    STACK_FRAME_FILEPATH_IGNORE_REGEXES_JAVA,
                ),
                "js" => (
                    STACK_FRAME_FUNCTION_IGNORE_REGEXES_JS,
                    STACK_FRAME_FILEPATH_IGNORE_REGEXES_JS,
                ),
                "lua" => (
                    STACK_FRAME_FUNCTION_IGNORE_REGEXES_LUA,
                    STACK_FRAME_FILEPATH_IGNORE_REGEXES_LUA,
                ),
                "python" => (
                    STACK_FRAME_FUNCTION_IGNORE_REGEXES_PYTHON,
                    STACK_FRAME_FILEPATH_IGNORE_REGEXES_PYTHON,
                ),
                "rust" => (
                    STACK_FRAME_FUNCTION_IGNORE_REGEXES_RUST,
                    STACK_FRAME_FILEPATH_IGNORE_REGEXES_RUST,
                ),
                &_ => (["^[^.]$"].as_slice(), ["^[^.]$"].as_slice()),
            })
            .unzip();
        *STACK_FRAME_FUNCTION_IGNORE_REGEXES.write().unwrap() = funcs
            .concat()
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
        *STACK_FRAME_FILEPATH_IGNORE_REGEXES.write().unwrap() = files
            .concat()
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
    }
}

impl Filter for Stacktrace {
    fn filter(&mut self) {
        // Compile function regexp.
        let function_regexes = STACK_FRAME_FUNCTION_IGNORE_REGEXES.read().unwrap();
        let rfunction = if !function_regexes.is_empty() {
            let rstring = function_regexes
                .iter()
                .fold(String::new(), |mut output, s| {
                    let _ = write!(output, "({s})|");
                    output
                });
            Regex::new(&rstring[0..rstring.len() - 1]).unwrap()
        } else {
            Regex::new(r"^[^.]$").unwrap()
        };

        // Compile file regexp.
        let file_regexes = STACK_FRAME_FILEPATH_IGNORE_REGEXES.read().unwrap();
        let rfile = if !file_regexes.is_empty() {
            let rstring = file_regexes.iter().fold(String::new(), |mut output, s| {
                let _ = write!(output, "({s})|");
                output
            });
            Regex::new(&rstring[0..rstring.len() - 1]).unwrap()
        } else {
            Regex::new(r"^[^.]$").unwrap()
        };

        // For libfuzzer: delete functions below LLVMFuzzerTestOneInput
        if let Some(pos) = &self
            .iter()
            .position(|x| x.function.contains("LLVMFuzzerTestOneInput"))
        {
            self.drain(pos + 1..);
        }

        // Remove trusted functions from stack trace
        *self = std::mem::take(self)
            .into_iter()
            .filter(|entry| (entry.function.is_empty() || !rfunction.is_match(&entry.function)))
            .filter(|entry| (entry.module.is_empty() || !rfile.is_match(&entry.module)))
            .filter(|entry| (entry.debug.file.is_empty() || !rfile.is_match(&entry.debug.file)))
            .collect();
        // Find repeating intervals in stacktrace
        let mut vec = get_interval_repetitions(self);
        while vec.iter().any(|el| !el) {
            let mut keep = vec.iter();
            *self = std::mem::take(self)
                .into_iter()
                .filter(|_| *keep.next().unwrap())
                .collect();
            vec = get_interval_repetitions(self);
        }
    }
}

/// Find repeating intervals in sequence
///
/// # Arguments
///
/// * `arr` - given sequence
///
/// # Return value
///
/// An vector of the same length as `arr`.
/// Vec\[i\] is false, if original element i is a duplicate in some loop.
fn get_interval_repetitions<T: PartialEq>(arr: &[T]) -> Vec<bool> {
    let len = arr.len();
    let mut indices = Vec::new();
    indices.resize(len, true);
    for i in 1..len / 2 + 1 {
        let mut start = len;
        let (iter1, iter2) = (arr[..len - i].iter(), arr[i..].iter());
        iter1.zip(iter2).enumerate().for_each(|(idx, (el1, el2))| {
            if el1 == el2 {
                if start == len {
                    start = idx;
                }
            } else if start != len {
                if idx - start >= i {
                    (start..idx - (idx - start) % i).for_each(|index| indices[index] = false);
                }
                start = len;
            }
        });
        if len - start >= 2 * i {
            (start..len - (len - start) % i - i).for_each(|index| indices[index] = false);
        }
    }
    indices
}

#[cfg(test)]
pub mod tests {
    use std::sync::RwLock;

    use crate::stacktrace::*;

    lazy_static::lazy_static! {
        static ref INITED_STACKFRAMES_FILTER: RwLock<bool> = RwLock::new(false);
    }

    /// Thread-safe initialization of all stackframe filters
    pub fn safe_init_ignore_stack_frames() {
        let mut is_inited = INITED_STACKFRAMES_FILTER.write().unwrap();
        if !*is_inited {
            *is_inited = true;
            init_ignored_frames!("cpp", "csharp", "go", "java", "js", "lua", "python", "rust");
        }
    }

    #[test]
    fn test_main_lorentz() {
        let tests = [
            "aa",
            "aaaaa",
            "aabcaabca",
            "bcabcabcacbaagfgfgfgf",
            "abcaacaacaac",
            "aacaacaacaac",
        ]
        .iter()
        .map(|x| x.chars().collect::<Vec<char>>())
        .collect::<Vec<_>>();

        fn convert_answer(indices: &[bool]) -> Vec<(usize, usize)> {
            let mut intervals = Vec::new();
            let len = indices.len();
            let mut start = len;
            indices.iter().enumerate().for_each(|(idx, el)| {
                if !*el {
                    if start == len {
                        start = idx;
                    }
                } else if start != len {
                    intervals.push((start, idx - 1));
                    start = len;
                }
            });
            if start != len {
                intervals.push((start, len - 1));
            }
            intervals
        }

        let answer = convert_answer(&get_interval_repetitions(&tests[0]));
        assert!(answer.contains(&(0, 0)));

        let answer = convert_answer(&get_interval_repetitions(&tests[1]));
        assert!(answer.contains(&(0, 3)));

        let answer = convert_answer(&get_interval_repetitions(&tests[2]));
        assert!(answer.contains(&(0, 4)));

        let answer = convert_answer(&get_interval_repetitions(&tests[3]));
        assert!(answer.contains(&(0, 5)));
        assert!(answer.contains(&(11, 11)));
        assert!(answer.contains(&(13, 18)));

        let answer = convert_answer(&get_interval_repetitions(&tests[4]));
        assert!(answer.contains(&(2, 7)));
        assert!(answer.contains(&(9, 9)));

        let answer = convert_answer(&get_interval_repetitions(&tests[5]));
        assert!(answer.contains(&(0, 9)));
    }
}
