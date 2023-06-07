use casr::util;
use libcasr::constants::*;
use libcasr::init_ignored_frames;
use libcasr::stacktrace::*;

use anyhow::{bail, Context, Result};
use clap::{Arg, ArgAction};
use rayon::iter::{IndexedParallelIterator, ParallelIterator};
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator};

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

/// Extract stack trace from casr (casr-san/casr-gdb) report
///
/// # Arguments
///
/// * `path` - path to the casrep
///
/// # Return value
///
/// Stack trace as a `Stacktrace` struct
fn stacktrace(path: &Path) -> Result<Stacktrace> {
    match util::report_from_file(path)?.filtered_stacktrace() {
        Ok(trace) => Ok(trace),
        Err(e) => bail!("{}. File {}", e, path.display()),
    }
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
fn make_clusters(inpath: &Path, outpath: Option<&Path>, jobs: usize) -> Result<u32> {
    // if outpath is "None" we consider that outpath and inpath are the same
    let outpath = outpath.unwrap_or(inpath);
    let dir = fs::read_dir(inpath).with_context(|| format!("File: {}", inpath.display()))?;

    let mut casreps: Vec<PathBuf> = dir
        .map(|path| path.unwrap().path())
        .filter(|s| s.extension().is_some() && s.extension().unwrap() == "casrep")
        .collect();
    let len = casreps.len();
    if len < 2 {
        bail!("{} reports, nothing to cluster...", len);
    }

    casreps.sort_by(|a, b| {
        a.file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .cmp(b.file_name().unwrap().to_str().unwrap())
    });

    // Start thread pool.
    let custom_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(jobs.min(len))
        .build()
        .unwrap();

    // Stacktraces from casreps
    let traces: RwLock<Vec<Stacktrace>> = RwLock::new(Vec::new());
    // Casreps with stacktraces, that we can parse
    let filtered_casreps: RwLock<Vec<PathBuf>> = RwLock::new(Vec::new());
    // Casreps with stacktraces, that we cannot parse
    let mut badreports: RwLock<Vec<PathBuf>> = RwLock::new(Vec::new());
    custom_pool.install(|| {
        (0..len).into_par_iter().for_each(|i| {
            if let Ok(trace) = stacktrace(casreps[i].as_path()) {
                traces.write().unwrap().push(trace);
                filtered_casreps.write().unwrap().push(casreps[i].clone());
            } else {
                badreports.write().unwrap().push(casreps[i].clone());
            }
        })
    });
    let stacktraces = traces.read().unwrap();
    let casreps = filtered_casreps.read().unwrap();
    let badreports = badreports.get_mut().unwrap();

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

    if stacktraces.len() < 2 {
        bail!("{} valid reports, nothing to cluster...", stacktraces.len());
    }

    let clusters = cluster_stacktraces(&stacktraces)?;

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
/// * `jobs` - number of jobs for deduplication process
///
/// # Return value
///
/// Number of reports before/after deduplication
fn deduplication(indir: &Path, outdir: Option<PathBuf>, jobs: usize) -> Result<(usize, usize)> {
    let dir = fs::read_dir(indir).with_context(|| {
        format!(
            "Error occurred while opening directory with Casr reports. File: {}",
            indir.display()
        )
    })?;
    let mut paths: Vec<PathBuf> = Vec::new();
    let (mut before, mut after) = (0usize, 0usize);
    for entry in dir.flatten() {
        if entry.metadata()?.is_dir() {
            let res = deduplication(
                entry.path().as_path(),
                outdir
                    .as_ref()
                    .map(|outdir| Path::new(&outdir).join(entry.file_name())),
                jobs,
            )?;
            before += res.0;
            after += res.1;
            continue;
        }
        if entry.path().extension().is_none() || entry.path().extension().unwrap() != "casrep" {
            continue;
        }
        paths.push(entry.path());
    }

    paths.sort_by(|a, b| a.file_name().unwrap().cmp(b.file_name().unwrap()));

    // Start thread pool.
    let custom_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(jobs.min(paths.len()))
        .build()
        .unwrap();

    let badrepidxs: RwLock<HashSet<usize>> = RwLock::new(HashSet::new());
    let stacktraces: RwLock<Vec<Stacktrace>> = RwLock::new(vec![Default::default(); paths.len()]);
    custom_pool.install(|| {
        paths.par_iter().enumerate().for_each(|(index, report)| {
            if let Ok(trace) = stacktrace(report.as_path()) {
                stacktraces.write().unwrap()[index] = trace;
            } else {
                badrepidxs.write().unwrap().insert(index);
            }
        })
    });

    let badrepidxs = badrepidxs.read().unwrap();
    let stacktraces = stacktraces.read().unwrap();

    let result = dedup_stacktraces(&stacktraces);

    if let Some(ref outdir) = outdir {
        fs::create_dir_all(outdir)?;
        (0..paths.len())
            .filter(|x| !badrepidxs.contains(x))
            .enumerate()
            .try_for_each(|(res_idx, true_idx)| {
                if result[res_idx] {
                    fs::copy(
                        &paths[true_idx],
                        Path::new(&outdir).join(paths[true_idx].file_name().unwrap()),
                    )?;
                    after += 1;
                }
                Ok::<(), anyhow::Error>(())
            })?;
    } else {
        (0..paths.len())
            .filter(|x| !badrepidxs.contains(x))
            .enumerate()
            .try_for_each(|(res_idx, true_idx)| {
                if !result[res_idx] {
                    fs::remove_file(&paths[true_idx])
                } else {
                    after += 1;
                    Ok(())
                }
            })?;
    }

    if !badrepidxs.is_empty() {
        let clerr = outdir
            .clone()
            .unwrap_or_else(|| indir.to_path_buf())
            .join("clerr");
        fs::create_dir_all(&clerr)?;
        for &index in badrepidxs.iter() {
            fs::copy(
                &paths[index],
                clerr.join(paths[index].file_name().unwrap().to_str().unwrap()),
            )?;
            if outdir.is_none() {
                fs::remove_file(&paths[index])?;
            }
        }
    }

    before += paths.len();

    Ok((before, after))
}

/// Merge new reports from input directory into output directory
///
/// # Arguments
///
/// * `input` - path to directory with new CASR reports
///
/// * `output` - path to output directory with CASR reports
///
/// # Return value
///
/// Number of merged reports
fn merge_dirs(input: &Path, output: &Path) -> Result<u64> {
    let dir = fs::read_dir(output).with_context(|| {
        format!(
            "Error occurred while opening directory with Casr reports. Directory: {}",
            output.display()
        )
    })?;

    let mut mainhash = HashSet::new();
    for entry in dir.flatten() {
        if entry.path().extension().is_some() && entry.path().extension().unwrap() == "casrep" {
            if let Ok(trace) = stacktrace(entry.path().as_path()) {
                mainhash.insert(trace);
            } else {
                bail!("Output directory corrupted, merge failed.");
            }
        }
    }

    let dir = fs::read_dir(input).with_context(|| {
        format!(
            "Error occurred while opening directory with Casr reports. Directory: {}",
            input.display()
        )
    })?;

    let mut new: u64 = 0;
    for entry in dir.flatten() {
        if entry.path().extension().is_some() && entry.path().extension().unwrap() == "casrep" {
            if let Ok(trace) = stacktrace(entry.path().as_path()) {
                if mainhash.insert(trace) {
                    let target = Path::new(&output).join(entry.file_name());
                    if target.exists() {
                        eprintln!(
                            "File with name {} already exists in OUTPUT_DIR.",
                            target.file_name().unwrap().to_str().unwrap()
                        );
                    } else {
                        fs::copy(entry.path().as_path(), &target)?;
                        new += 1;
                    }
                }
            } else {
                eprintln!(
                    "Cannot extract stack trace from {}. Skipping this report.",
                    entry.file_name().into_string().unwrap()
                );
            }
        }
    }
    Ok(new)
}

fn main() -> Result<()> {
    let matches = clap::Command::new("casr-cluster")
        .version(clap::crate_version!())
        .about("Tool for clustering CASR reports")
        .term_width(90)
        .arg(
            Arg::new("similarity")
                .short('s')
                .long("similarity")
                .action(ArgAction::Set)
                .num_args(2)
                .value_parser(clap::value_parser!(PathBuf))
                .value_names(["CASREP1", "CASREP2"])
                .help("Similarity between two CASR reports"),
        )
        .arg(
            Arg::new("clustering")
                .short('c')
                .long("cluster")
                .action(ArgAction::Set)
                .num_args(1..=2)
                .value_parser(clap::value_parser!(PathBuf))
                .value_names(["INPUT_DIR", "OUTPUT_DIR"])
                .help(
                    "Cluster CASR reports. If two directories are set, \
                    clusters will be placed in the second directory. If one \
                    directory is provided, clusters will be placed there, but \
                    reports in this directory will not be deleted.",
                ),
        )
        .arg(
            Arg::new("deduplication")
                .short('d')
                .long("deduplicate")
                .action(ArgAction::Set)
                .num_args(1..=2)
                .value_parser(clap::value_parser!(PathBuf))
                .value_names(["INPUT_DIR", "OUTPUT_DIR"])
                .help(
                    "Deduplicate CASR reports. If two directories are set, \
                    deduplicated reports are copied to the second directory. \
                    If one directory is provided, duplicated reports are deleted.",
                ),
        )
        .arg(
            Arg::new("merge")
                .short('m')
                .long("merge")
                .action(ArgAction::Set)
                .num_args(2)
                .value_parser(clap::value_parser!(PathBuf))
                .value_names(["INPUT_DIR", "OUTPUT_DIR"])
                .help(
                    "Merge INPUT_DIR into OUTPUT_DIR. Only new CASR reports from \
                    INPUT_DIR will be added to OUTPUT_DIR.",
                ),
        )
        .arg(
            Arg::new("ignore")
                .long("ignore")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .value_name("FILE")
                .help("File with regular expressions for functions and file paths that should be ignored"),
        )
        .arg(
            Arg::new("jobs")
                .long("jobs")
                .short('j')
                .value_name("N")
                .action(ArgAction::Set)
                .help("Number of parallel jobs to collect CASR reports")
                .value_parser(clap::value_parser!(u32).range(1..))
        )
        .get_matches();
    init_ignored_frames!("cpp", "rust", "python", "go");

    let jobs = if let Some(jobs) = matches.get_one::<u32>("jobs") {
        *jobs as usize
    } else {
        std::cmp::max(1, num_cpus::get() / 2)
    };

    if let Some(path) = matches.get_one::<PathBuf>("ignore") {
        util::add_custom_ignored_frames(path)?;
    }
    if matches.contains_id("similarity") {
        let casreps: Vec<&PathBuf> = matches.get_many::<PathBuf>("similarity").unwrap().collect();
        println!(
            "{0:.5}",
            similarity(&stacktrace(casreps[0])?, &stacktrace(casreps[1])?)
        );
    } else if matches.contains_id("clustering") {
        let paths: Vec<&PathBuf> = matches.get_many::<PathBuf>("clustering").unwrap().collect();

        let result = make_clusters(paths[0], paths.get(1).map(|x| x.as_path()), jobs)?;
        println!("Number of clusters: {result}");
    } else if matches.contains_id("deduplication") {
        let paths: Vec<&PathBuf> = matches
            .get_many::<PathBuf>("deduplication")
            .unwrap()
            .collect();
        let (before, after) = deduplication(paths[0], paths.get(1).map(|x| x.to_path_buf()), jobs)?;
        println!("Number of reports before deduplication: {before}");
        println!("Number of reports after deduplication: {after}");
    } else if matches.contains_id("merge") {
        let paths: Vec<&PathBuf> = matches.get_many::<PathBuf>("merge").unwrap().collect();
        let new = merge_dirs(paths[0], paths[1])?;
        println!(
            "Merged {} new reports into {} directory",
            new,
            paths[1].display()
        );
    }

    Ok(())
}
