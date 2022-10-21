extern crate anyhow;
extern crate casr;
extern crate clap;
extern crate gdb_command;
extern crate num_cpus;
extern crate rayon;
extern crate regex;
extern crate serde_json;

use anyhow::Context;
use casr::error;
use casr::error::Error;
use clap::{App, Arg};
use gdb_command::mappings::*;
use gdb_command::stacktrace::*;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::io::BufReader;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::Stdio;
use std::sync::RwLock;

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
fn similarity(first: &Stacktrace, second: &Stacktrace) -> f64 {
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

/// Extract stack trace from casr(caesar) report
///
/// # Arguments
///
/// * `path` - path to the casrep
///
/// # Return value
///
/// Stack trace as a `Stacktrace` struct
fn stacktrace(path: &Path) -> error::Result<Stacktrace> {
    // Opening file and reading it
    let file = std::fs::File::open(path);
    if file.is_err() {
        return Err(Error::Cluster(format!(
            "Error with opening Casr report: {}",
            path.display()
        )));
    }
    let file = file.unwrap();
    let reader = BufReader::new(file);

    let u = serde_json::from_reader(reader);
    if u.is_err() {
        return Err(Error::Cluster(format!(
            "Json parse error. File: {}",
            path.display()
        )));
    }
    let u: serde_json::Value = u.unwrap();

    // Search stacktrace
    if let Some(arrtrace) = u.get("Stacktrace") {
        if let Some(arrtrace) = arrtrace.as_array() {
            let mut trace = Vec::new();
            arrtrace.iter().for_each(|x| {
                if let Some(entry) = x.as_str() {
                    trace.push(entry.to_string());
                }
            });
            let mut rawtrace = if let Some(asan_array) = u.get("AsanReport") {
                if let Some(asan_array) = asan_array.as_array() {
                    if asan_array.iter().next().is_some() {
                        casr::asan::stacktrace_from_asan(&trace)
                            .with_context(|| format!("File: {}", path.display()))?
                    } else {
                        Stacktrace::from_gdb(&trace.join("\n"))
                            .with_context(|| format!("File: {}", path.display()))?
                    }
                } else {
                    return Err(Error::Cluster(format!(
                        "Error while parsing AsanReport. File: {}",
                        path.display()
                    )));
                }
            } else {
                Stacktrace::from_gdb(&trace.join("\n"))
                    .with_context(|| format!("File: {}", path.display()))?
            };

            // For libfuzzer: delete functions below LLVMFuzzerTestOneInput
            if let Some(pos) = &rawtrace
                .iter()
                .position(|x| x.function.contains("LLVMFuzzerTestOneInput"))
            {
                rawtrace.drain(pos + 1..);
            }

            if rawtrace.is_empty() {
                return Err(Error::Cluster(
                    "Current stack trace length is null".to_string(),
                ));
            }

            // Get Proc mappings from Casr report
            if let Some(arrtrace) = u.get("ProcMaps") {
                if let Some(arrtrace) = arrtrace.as_array() {
                    if !arrtrace.is_empty() {
                        let mut trace = Vec::new();
                        arrtrace.iter().for_each(|x| {
                            if let Some(entry) = x.as_str() {
                                trace.push(entry.to_string());
                            }
                        });
                        let trace = trace.join("\n");
                        let mappings = MappedFiles::from_gdb(&trace)
                            .with_context(|| format!("File: {}", path.display()))?;
                        rawtrace.compute_module_offsets(&mappings);
                    }
                }
            }

            // Remove abort and libc functions from stack trace
            if rawtrace[0].function.contains("__GI_raise") {
                let re = Regex::new(r"libc-\d{1}.\d{1, 3}.so").unwrap();
                let pos = rawtrace
                    .iter()
                    .rposition(|x| !x.module.is_empty() && re.is_match(&x.module));
                if let Some(pos) = pos {
                    rawtrace.drain(0..pos + (pos != rawtrace.len() - 1) as usize);
                }
            }

            return Ok(rawtrace);
        }
    }
    Err(Error::Cluster(format!(
        "Json parse error, file: {}",
        path.display()
    )))
}

/// Perform the clustering of casreps
///
/// # Arguments
///
/// * `inpath` - path to targets
///
/// * `outpath` - target directory for clusters
///
/// * `jobs` - number of jobs for clustering process
///
/// # Return value
///
/// Number of clusters
pub fn make_clusters(inpath: &Path, outpath: Option<&Path>, jobs: usize) -> error::Result<u32> {
    // if outpath is "None" we consider that outpath and inpath are the same
    let outpath = outpath.unwrap_or(inpath);
    let dir = fs::read_dir(inpath).with_context(|| format!("File: {}", inpath.display()))?;

    let casreps: Vec<PathBuf> = dir
        .map(|path| path.unwrap().path())
        .filter(|s| s.extension().is_some() && s.extension().unwrap() == "casrep")
        .collect();
    let len = casreps.len();
    if len < 2 {
        return Err(Error::Cluster(format!(
            "{} reports, nothing to cluster...",
            len
        )));
    }

    // Start thread pool.
    rayon::ThreadPoolBuilder::new()
        .num_threads(jobs.min(len))
        .build_global()
        .unwrap();

    let mut tmp_lines: Vec<String> = Vec::new();
    tmp_lines.resize(len, "".to_string());
    // Lines in compressed distance matrix
    let mut lines: RwLock<Vec<String>> = RwLock::new(tmp_lines);

    // Stacktraces from casreps
    let traces: RwLock<Vec<Stacktrace>> = RwLock::new(Vec::new());
    // Casreps with stacktraces, that we can parse
    let filtered_casreps: RwLock<Vec<PathBuf>> = RwLock::new(Vec::new());
    // Casreps with stacktraces, that we cannot parse
    let mut badreports: RwLock<Vec<PathBuf>> = RwLock::new(Vec::new());

    (0..len).into_par_iter().for_each(|i| {
        if let Ok(trace) = stacktrace(casreps[i].as_path()) {
            traces.write().unwrap().push(trace);
            filtered_casreps.write().unwrap().push(casreps[i].clone());
        } else {
            badreports.write().unwrap().push(casreps[i].clone());
        }
    });
    let stacktraces = traces.read().unwrap();
    let casreps = filtered_casreps.read().unwrap();
    let badreports = badreports.get_mut().unwrap();
    let len = casreps.len();
    // Writing compressed distance matrix to help file
    (0..len).into_par_iter().for_each(|i| {
        let mut tmp_str = String::new();
        for j in i + 1..len {
            tmp_str += format!(
                "{0:.3} ",
                1.0 - similarity(&stacktraces[i], &stacktraces[j])
            )
            .as_str();
        }
        let mut lines = lines.write().unwrap();
        lines[i] = tmp_str;
    });

    let python_cluster_script =
        "import numpy as np;\
        from scipy.cluster.hierarchy import fcluster, linkage;\
        a = np.fromstring(input(), dtype=float, sep=' ');\
        print(*fcluster(linkage([a] if type(a.tolist()) is float else a, method=\"complete\"), 0.3, criterion=\"distance\"))";

    let mut python = Command::new("python3")
        .args(&["-c", python_cluster_script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    {
        let python_stdin = python.stdin.as_mut().unwrap();
        python_stdin
            .write_all(lines.get_mut().unwrap().join("").as_bytes())
            .with_context(|| "Error while writing to stdin of python script".to_string())?;
    }
    let python = python.wait_with_output()?;

    if !python.status.success() {
        return Err(Error::Cluster(format!(
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
        return Err(Error::Cluster(format!(
            "Number of casreps({}) differs from array length({}) from python",
            len,
            clusters.len()
        )));
    }

    // Cluster formation
    let cluster_cnt = *clusters.iter().max().unwrap();
    for i in 1..=cluster_cnt {
        fs::create_dir_all(format!("{}/cl{}", &outpath.display(), i))?;
    }
    for i in 0..clusters.len() {
        fs::copy(
            &casreps[i],
            format!(
                "{}/cl{}/{}",
                &outpath.display(),
                &clusters[i],
                &casreps[i].file_name().unwrap().to_str().unwrap()
            ),
        )?;
    }
    if !badreports.is_empty() {
        fs::create_dir_all(format!("{}/clerr", &outpath.display()))?;
        for report in badreports {
            fs::copy(
                &report,
                format!(
                    "{}/clerr/{}",
                    &outpath.display(),
                    &report.file_name().unwrap().to_str().unwrap()
                ),
            )?;
        }
    }
    Ok(cluster_cnt)
}

/// Remove duplicate casreps
///
/// # Arguments
///
/// * `indir` - path to targets
///
/// * `outdir` - target directory for deduplication
///
/// # Return value
///
/// Number of reports before/after deduplication
fn dedup(indir: &Path, outdir: Option<PathBuf>) -> error::Result<(usize, usize)> {
    let dir = fs::read_dir(indir).with_context(|| {
        format!(
            "Error occurred while opening directory with Casr reports. File: {}",
            indir.display()
        )
    })?;
    let mut paths: Vec<fs::DirEntry> = Vec::new();
    let (mut before, mut after) = (0usize, 0usize);
    for entry in dir.flatten() {
        if entry.metadata()?.is_dir() {
            let res = dedup(
                entry.path().as_path(),
                outdir
                    .as_ref()
                    .map(|outdir| Path::new(&outdir).join(&entry.file_name())),
            )?;
            before += res.0;
            after += res.1;
            continue;
        }
        if entry.path().extension().is_none() || entry.path().extension().unwrap() != "casrep" {
            continue;
        }
        paths.push(entry);
    }

    let mut casreps = HashSet::new();
    let mut badreports: Vec<PathBuf> = Vec::new();

    if let Some(ref outdir) = outdir {
        fs::create_dir_all(outdir)?;

        for x in &paths {
            let trace = match stacktrace(x.path().as_path()) {
                Ok(tr) => tr,
                Err(_) => {
                    badreports.push(x.path());
                    continue;
                }
            };
            if casreps.insert(trace) {
                fs::copy(
                    &x.path().as_path(),
                    &Path::new(&outdir).join(&x.file_name()),
                )?;
            }
        }
    } else {
        for x in &paths {
            let trace = match stacktrace(x.path().as_path()) {
                Ok(tr) => tr,
                Err(_) => {
                    badreports.push(x.path());
                    continue;
                }
            };
            if !casreps.insert(trace) {
                fs::remove_file(&x.path().as_path())?;
            }
        }
    }

    if !badreports.is_empty() {
        let clerr = outdir.unwrap_or_else(|| indir.to_path_buf()).join("clerr");
        fs::create_dir_all(&clerr)?;
        for report in badreports {
            fs::copy(
                &report,
                clerr.join(&report.file_name().unwrap().to_str().unwrap()),
            )?;
        }
    }

    before += paths.len();
    after += casreps.len();

    Ok((before, after))
}

fn main() -> error::Result<()> {
    let matches = App::new("casr-cluster")
        .version("2.1.0")
        .author("Andrey Fedotov  <fedotoff@ispras.ru>, Alexey Vishnyakov <vishnya@ispras.ru>, Georgy Savidov <avgor46@ispras.ru>")
        .about("Tool for clustering CASR reports")
        .term_width(90)
        .arg(
            Arg::new("similarity")
                .short('s')
                .long("similarity")
                .takes_value(true)
                .min_values(2)
                .max_values(2)
                .value_names(&["CASREP1", "CASREP2"])
                .help("Similarity between two CASR reports"),
        )
        .arg(
            Arg::new("clustering")
                .short('c')
                .long("cluster")
                .takes_value(true)
                .min_values(1)
                .max_values(2)
                .value_name("INPUT_DIR> <OUTPUT_DIR")
                .help("Cluster CASR reports. If two directories are set, clusters will be placed in the second directory. If one directory is provided, clusters will be placed there, but reports in this directory will not be deleted."),
        )
        .arg(
            Arg::new("deduplication")
                .short('d')
                .long("deduplicate")
                .takes_value(true)
                .min_values(1)
                .max_values(2)
                .value_name("INPUT_DIR> <OUTPUT_DIR")
                .help("Deduplicate CASR reports. If two directories are set, deduplicated reports are copied to the second directory. If one directory is provided, duplicated reports are deleted."),
        )
        .arg(
            Arg::new("jobs")
                .long("jobs")
                .short('j')
                .value_name("N")
                .takes_value(true)
                .help("Number of parallel jobs to collect CASR reports")
                .validator(|arg| {
                    if let Ok(x) = arg.parse::<u64>() {
                        if x > 0 {
                            return Ok(());
                        }
                    }
                    Err(String::from("Couldn't parse jobs value"))
                }),
        )
        .get_matches();

    if matches.is_present("similarity") {
        let casreps: Vec<&Path> = matches
            .values_of("similarity")
            .unwrap()
            .map(Path::new)
            .collect();
        println!(
            "{0:.5}",
            similarity(&stacktrace(casreps[0])?, &stacktrace(casreps[1])?)
        );
    } else if matches.is_present("clustering") {
        let paths: Vec<&Path> = matches
            .values_of("clustering")
            .unwrap()
            .map(Path::new)
            .collect();

        let jobs = if let Some(jobs) = matches.value_of("jobs") {
            jobs.parse::<usize>().unwrap()
        } else {
            std::cmp::max(1, (num_cpus::get() / 2) as usize)
        };

        let result = make_clusters(paths[0], paths.get(1).cloned(), jobs)?;
        println!("Number of clusters: {}", result);
    } else if matches.is_present("deduplication") {
        let paths: Vec<&Path> = matches
            .values_of("deduplication")
            .unwrap()
            .map(Path::new)
            .collect();
        let (before, after) = dedup(paths[0], paths.get(1).map(|x| x.to_path_buf()))?;
        println!("Number of reports before deduplication: {}", before);
        println!("Number of reports after deduplication: {}", after);
    }

    Ok(())
}
