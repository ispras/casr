//! Provides API's for parsing, filtering, deduplication and clustering.
extern crate kodama;
extern crate lazy_static;

use crate::constants::{
    STACK_FRAME_FILEPATH_IGNORE_REGEXES_CPP, STACK_FRAME_FILEPATH_IGNORE_REGEXES_GO,
    STACK_FRAME_FILEPATH_IGNORE_REGEXES_JAVA, STACK_FRAME_FILEPATH_IGNORE_REGEXES_JS,
    STACK_FRAME_FILEPATH_IGNORE_REGEXES_PYTHON, STACK_FRAME_FILEPATH_IGNORE_REGEXES_RUST,
    STACK_FRAME_FUNCTION_IGNORE_REGEXES_CPP, STACK_FRAME_FUNCTION_IGNORE_REGEXES_GO,
    STACK_FRAME_FUNCTION_IGNORE_REGEXES_JAVA, STACK_FRAME_FUNCTION_IGNORE_REGEXES_JS,
    STACK_FRAME_FUNCTION_IGNORE_REGEXES_PYTHON, STACK_FRAME_FUNCTION_IGNORE_REGEXES_RUST,
};
use crate::error::*;
use core::f64::MAX;
use kodama::{linkage, Method};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Write};
use std::path::PathBuf;
use std::sync::RwLock;

// Re-export types from gdb_command for convenient use from Casr library
/// Represents the information about stack trace.
pub type Stacktrace = gdb_command::stacktrace::Stacktrace;
/// Represents the debug information of one frame in stack trace.
pub type DebugInfo = gdb_command::stacktrace::DebugInfo;
/// Represents the information about one line of the stack trace.
pub type StacktraceEntry = gdb_command::stacktrace::StacktraceEntry;

/// Represents the information about CASR report
pub type ReportInfo = (PathBuf, (Stacktrace, String));

lazy_static::lazy_static! {
    /// Regular expressions for functions to be ignored.
    pub static ref STACK_FRAME_FUNCTION_IGNORE_REGEXES: RwLock<Vec<String>> = RwLock::new(
        Vec::new());
    /// Regular expressions for file paths to be ignored.
    pub static ref STACK_FRAME_FILEPATH_IGNORE_REGEXES: RwLock<Vec<String>> = RwLock::new(
        Vec::new());
}

/// Threshold for clusters diameter
const THRESHOLD: f64 = 0.3;

/// Relation between a CASR report and a cluster
pub enum Relation {
    /// The CASR report is a duplicate of one from cluster
    Dup,
    /// The CASR report is "inside" the cluster with some proximity measure
    Inner(f64),
    /// The CASR report is "outside" the cluster with some proximity measure
    Outer(f64),
    /// The CASR report is out of threshold
    Oot,
}

/// Cluster accumulation strategy
#[derive(Clone, Copy, Debug)]
pub enum AccumStrategy {
    /// Argmin (diam (cluster + {new}) - diam (cluster))
    Delta,
    /// Argmin diam (cluster + {new})
    Diam,
    /// Argmin dist (cluster, {new})
    Dist,
}

/// Cluster tolerance level to new CASR reports
#[derive(Clone, Copy, Debug)]
pub enum ToleranceLevel {
    /// May insert any "Inner" and "Outer" CASR reports
    Loyal,
    /// May insert only "Inner" CASR reports
    Hard,
    /// May insert any "Inner" CASR reports
    /// But "Outers" may be added only as subclusters after their clustering
    Soft,
}

/// Structure provides an abstraction for cluster with CASR reports
pub struct Cluster {
    /// Cluster number
    pub number: usize,
    /// Cluster report paths
    paths: Vec<PathBuf>,
    /// Cluster report stacktraces
    stacktraces: Vec<Stacktrace>,
    /// Cluster diameter
    diam: Option<f64>,
    /// Cluster report crashlines
    crashlines: HashMap<String, usize>,
}

impl Cluster {
    /// Create new `Cluster`
    pub fn new(
        number: usize,
        paths: Vec<PathBuf>,
        stacktraces: Vec<Stacktrace>,
        crashlines: Vec<String>,
    ) -> Self {
        let mut unique_crashlines: HashMap<String, usize> = HashMap::new();
        for (i, crashline) in crashlines.into_iter().enumerate() {
            unique_crashlines.insert(crashline, i);
        }
        Cluster {
            number,
            paths,
            stacktraces,
            diam: None,
            crashlines: unique_crashlines,
        }
    }
    /// Get CASR report paths
    pub fn paths(&self) -> &Vec<PathBuf> {
        &self.paths
    }
    /// Get CASR report stactraces
    pub fn stacktraces(&self) -> &Vec<Stacktrace> {
        &self.stacktraces
    }
    /// Add new CASR report to cluster
    ///
    /// # Arguments
    ///
    /// * `stacktrace` - new CASR report stacktrace
    ///
    /// * `crashline` - new CASR report crashline
    ///
    /// * `dedup` - deduplicate crashline, if true
    ///
    /// # Return value
    ///
    /// `true` if new CASR report may be added,
    /// `false` if report is duplicate of someone else
    pub fn insert(
        &mut self,
        path: PathBuf,
        stacktrace: Stacktrace,
        crashline: String,
        dedup: bool,
    ) -> bool {
        if dedup && !crashline.is_empty() && self.crashlines.contains_key(&crashline) {
            return false;
        }
        self.paths.push(path);
        self.stacktraces.push(stacktrace);
        self.diam = None;
        self.crashlines.insert(crashline, self.paths.len() - 1);
        true
    }
    /// Get cluster diameter
    pub fn diam(&mut self) -> f64 {
        if self.diam.is_none() {
            self.diam = Some(diam(&self.stacktraces));
        }
        self.diam.unwrap()
    }
    /// Get "relation" between new report and specified cluster
    ///
    /// # Arguments
    ///
    /// * `new` - new report stacktrace
    ///
    /// * `inner_strategy` - cluster accumulation strategy if `new` is "inner"
    ///
    /// * `inner_strategy` - cluster accumulation strategy if `new` is "outer"
    ///
    /// # Return value
    ///
    /// `Relation` enum with proximity measure according specified strategy
    pub fn relation(
        &mut self,
        new: &Stacktrace,
        inner_strategy: AccumStrategy,
        outer_strategy: AccumStrategy,
    ) -> Relation {
        let diam = self.diam();
        let mut min = MAX;
        let mut max = 0f64;
        for stacktrace in self.stacktraces() {
            let dist = 1.0 - similarity(new, stacktrace);
            if dist == 0.0 {
                return Relation::Dup;
            } else if dist > THRESHOLD {
                return Relation::Oot;
            }
            if dist < min {
                min = dist;
            }
            if dist > max {
                max = dist;
            }
        }
        if diam >= max {
            // Inner
            let rel = match inner_strategy {
                // Delta is a nonsensical strategy in this case
                AccumStrategy::Diam => diam,
                _ => min,
            };
            Relation::Inner(rel)
        } else {
            // Outer
            let rel = match outer_strategy {
                AccumStrategy::Diam => max,
                AccumStrategy::Delta => max - diam,
                AccumStrategy::Dist => min,
            };
            Relation::Outer(rel)
        }
    }
    /// Check if cluster may be merged with another one
    pub fn may_merge(&self, cluster: &Cluster) -> bool {
        let mut stacktraces1 = self.stacktraces.clone();
        let mut stacktraces2 = cluster.stacktraces().clone();
        stacktraces1.append(&mut stacktraces2);
        diam(&stacktraces1) < THRESHOLD
    }
    /// Convert cluster to vector of reports
    pub fn reports(&self) -> Vec<ReportInfo> {
        let mut reports: Vec<ReportInfo> = Vec::new();
        let mut crashlines = self.crashlines.clone();
        for (i, path) in self.paths.iter().enumerate() {
            // Get crashline for cur casrep
            let mut crashline = String::new();
            for (line, &number) in &crashlines {
                if number == i {
                    crashline = line.to_string();
                    break;
                }
            }
            // Drop cur crashline from crashlines
            crashlines.remove(&crashline);
            // Update results
            reports.push((path.clone(), (self.stacktraces[i].clone(), crashline)));
        }
        reports
    }
}

/// Generate clusters from CASR report info
///
/// # Arguments
///
/// * `reports` - slice of report info: path, stacktrace, crashline
///
/// * `offset` - cluster enumerate offset
///
/// * `dedup` - deduplicate crashline, if true
///
/// # Return value
///
/// * `HashMap` of `Cluster`
/// * Number of valid casreps before crashiline deduplication
/// * Number of valid casreps after crashiline deduplication
pub fn gen_clusters(
    reports: &[ReportInfo],
    offset: usize,
    dedup: bool,
) -> Result<(HashMap<usize, Cluster>, usize, usize)> {
    // Unzip casrep info
    let (casreps, (stacktraces, crashlines)): (Vec<_>, (Vec<_>, Vec<_>)) =
        reports.iter().cloned().unzip();
    let len = casreps.len();
    // Get stacktraces cluster numbers
    let mut numbers = cluster_stacktraces(&stacktraces)?;
    // Deduplicate by crashiline
    let after = if dedup {
        dedup_crashlines(&crashlines, &mut numbers)
    } else {
        len
    };
    // Create clusters
    let mut clusters: HashMap<usize, Cluster> = HashMap::new();
    for i in 0..len {
        if numbers[i] == 0 {
            // Skip casreps with duplicate crashlines
            continue;
        }
        let number = numbers[i] + offset;
        // Add new cluster if not exists
        clusters
            .entry(number)
            .or_insert_with(|| Cluster::new(number, Vec::new(), Vec::new(), Vec::new()));
        // Update cluster
        clusters.get_mut(&number).unwrap().insert(
            casreps[i].to_path_buf(),
            stacktraces[i].to_vec(),
            crashlines[i].to_string(),
            dedup,
        );
    }
    Ok((clusters, len, after))
}

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

    // Get hierarchical clustering binary tree
    let dendrogram = linkage(&mut condensed_dissimilarity_matrix, len, Method::Complete);

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

/// Perform crashline deduplication for each cluster:
/// Reset Vec\[i\] to 0 if report crashline is duplicate of some other.
///
/// # Arguments
///
/// * `crashlines` - slice of crashlines as String
///
/// * 'clusters' - A vector of the same length as `crashlines`.
/// Vec\[i\] is the flat cluster number to which original casrep i belongs.
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

/// Get diameter of specified cluster
///
/// # Arguments
///
/// * `stacktraces` - cluster represented as slice of `Stacktrace` structures
///
/// # Return value
///
/// Value of diameter
fn diam(stacktraces: &[Stacktrace]) -> f64 {
    let mut diam = 0f64;
    let len = stacktraces.len();
    for i in 0..len {
        for j in i + 1..len {
            let dist = 1.0 - similarity(&stacktraces[i], &stacktraces[j]);
            if dist > diam {
                diam = dist;
            }
        }
    }
    diam
}

/// Get "a" subcoefficient silhouette coefficient calculating for given stacktrace
/// Read more: https://en.wikipedia.org/wiki/Silhouette_(clustering)#Definition
///
/// # Arguments
///
/// * `num` - given stacktrace number
///
/// * `stacktraces` - cluster represented as slice of `Stacktrace` structures
///
/// # Return value
///
/// "a" subcoefficient silhouette coefficient
fn sil_subcoef_a(num: usize, stacktraces: &[Stacktrace]) -> f64 {
    let mut sum = 0f64;
    for (i, stacktrace) in stacktraces.iter().enumerate() {
        if i == num {
            continue;
        }
        sum += 1.0 - similarity(&stacktraces[num], stacktrace);
    }
    sum / (stacktraces.len() - 1) as f64
}

/// Get "b" subcoefficient silhouette coefficient calculating for given stacktrace
/// Read more: https://en.wikipedia.org/wiki/Silhouette_(clustering)#Definition
///
/// # Arguments
///
/// * `num` - given stacktrace number
///
/// * `i` - cluster number of given stacktrace
///
/// * `clusters` - a vector of clusters represented as slice of `Stacktrace` structures
///
/// # Return value
///
/// "b" subcoefficient silhouette coefficient
fn sil_subcoef_b(num: usize, i: usize, clusters: &[Vec<Stacktrace>]) -> f64 {
    let mut min = MAX;
    for (j, cluster) in clusters.iter().enumerate() {
        if j == i {
            continue;
        }
        let mut sum = 0f64;
        for stacktrace in cluster {
            sum += 1.0 - similarity(&clusters[i][num], stacktrace);
        }
        let res = sum / cluster.len() as f64;
        if res < min {
            min = res;
        }
    }
    min
}

/// Get silhouette coefficient calculating for given stacktrace
/// Read more: https://en.wikipedia.org/wiki/Silhouette_(clustering)#Definition
///
/// # Arguments
///
/// * `num` - given stacktrace number
///
/// * `i` - cluster number of given stacktrace
///
/// * `clusters` - a vector of clusters represented as slice of `Stacktrace` structures
///
/// # Return value
///
/// Silhouette coefficient
pub fn sil_coef(num: usize, i: usize, clusters: &[Vec<Stacktrace>]) -> f64 {
    if clusters[i].len() != 1 {
        let a = sil_subcoef_a(num, &clusters[i]);
        let b = sil_subcoef_b(num, i, clusters);
        (b - a) / a.max(b)
    } else {
        0f64
    }
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
                "python" => (
                    STACK_FRAME_FUNCTION_IGNORE_REGEXES_PYTHON,
                    STACK_FRAME_FILEPATH_IGNORE_REGEXES_PYTHON,
                ),
                "rust" => (
                    STACK_FRAME_FUNCTION_IGNORE_REGEXES_RUST,
                    STACK_FRAME_FILEPATH_IGNORE_REGEXES_RUST,
                ),
                "cpp" => (
                    STACK_FRAME_FUNCTION_IGNORE_REGEXES_CPP,
                    STACK_FRAME_FILEPATH_IGNORE_REGEXES_CPP,
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
mod tests {
    use crate::stacktrace::*;

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
