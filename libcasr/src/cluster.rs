//! Provides API's for cluster manipulating.
use crate::error::*;
use crate::stacktrace::*;

use core::f64::MAX;
use std::collections::HashMap;
use std::path::PathBuf;

/// Represents the information about CASR report: path, stacktrace and crashline
pub type ReportInfo = (PathBuf, (Stacktrace, String));

/// Relation between a CASR report and a cluster
pub enum Relation {
    /// The CASR report is a duplicate of one from cluster
    Dup,
    /// The CASR report is "inside" the cluster with some proximity measure
    Inner(f64),
    /// The CASR report is "outside" the cluster
    Outer,
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
            if unique_crashlines.contains_key(&crashline) {
                continue;
            }
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
    /// Perform CASR reports clustering
    ///
    /// # Arguments
    ///
    /// * `reports` - slice of `ReportInfo`
    ///
    /// * `offset` - cluster enumerate offset
    ///
    /// * `dedup` - deduplicate crashline, if true
    ///
    /// # Return value
    ///
    /// * `HashMap` of `Cluster` with cluster number as key
    /// * Number of valid casreps before crashline deduplication
    /// * Number of valid casreps after crashline deduplication
    pub fn cluster_reports(
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
        // Deduplicate by crashline
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
    /// # Return value
    ///
    /// `Relation` enum with proximity measure according specified strategy
    pub fn relation(&mut self, new: &Stacktrace) -> Relation {
        let diam = self.diam();
        let mut max = 0f64;
        for stacktrace in self.stacktraces() {
            let dist = 1.0 - similarity(new, stacktrace);
            if dist == 0.0 {
                return Relation::Dup;
            } else if dist > THRESHOLD {
                return Relation::Outer;
            }
            if dist > max {
                max = dist;
            }
        }
        if diam >= max {
            // Inner
            Relation::Inner(diam)
        } else {
            // Outer
            Relation::Outer
        }
    }
    /// Get complete distance between clusters
    /// NOTE: Result also can be interpreted as diameter of cluster merge result
    pub fn dist(cluster1: &Cluster, cluster2: &Cluster) -> f64 {
        let mut stacktraces1 = cluster1.stacktraces().clone();
        let mut stacktraces2 = cluster2.stacktraces().clone();
        stacktraces1.append(&mut stacktraces2);
        diam(&stacktraces1)
    }
    /// Get complete distance between cluster and report
    /// NOTE: Result also can be interpreted as diameter of cluster merge result
    pub fn dist_rep(cluster: &Cluster, report: &ReportInfo) -> f64 {
        let (_, (trace, _)) = report;
        if let Some(max) = cluster
            .stacktraces()
            .iter()
            .map(|s| 1.0 - similarity(s, trace))
            .max_by(|a, b| a.total_cmp(b))
        {
            max
        } else {
            0f64
        }
    }
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
fn sil_coef(num: usize, i: usize, clusters: &[Vec<Stacktrace>]) -> f64 {
    if clusters[i].len() != 1 {
        let a = sil_subcoef_a(num, &clusters[i]);
        let b = sil_subcoef_b(num, i, clusters);
        (b - a) / a.max(b)
    } else {
        0f64
    }
}

/// Get average silhouette coefficient calculating for given stacktraces
/// Read more: https://en.wikipedia.org/wiki/Silhouette_(clustering)#Definition
///
/// # Arguments
///
/// * `clusters` - a vector of clusters represented as slice of `Stacktrace` structures
///
/// * `size` - total amount of elements in clusters
///
/// # Return value
///
/// Average silhouette coefficient
pub fn avg_sil_coef(clusters: &[Vec<Stacktrace>], size: usize) -> f64 {
    // Init sil sum
    let mut sum = 0f64;
    // Calculate silhouette coefficient for each casrep
    for i in 0..clusters.len() {
        for num in 0..clusters[i].len() {
            let sil = sil_coef(num, i, clusters);
            sum += sil;
        }
    }
    sum / size as f64
}
