use casr::util;
use libcasr::{cluster::*, init_ignored_frames, stacktrace::*};

use anyhow::{Context, Result, bail};
use clap::{Arg, ArgAction, builder::FalseyValueParser};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

/// Extract stack trace from casr report
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
/// * `dedup` - deduplicate casrep by crashline for each cluster, if true
///
/// # Return value
///
/// * Number of clusters
/// * Number of valid casreps before crashline deduplication
/// * Number of valid casreps after crashline deduplication
fn make_clusters(
    inpath: &Path,
    outpath: Option<&Path>,
    jobs: usize,
    dedup: bool,
) -> Result<(usize, usize, usize)> {
    // if outpath is "None" we consider that outpath and inpath are the same
    let outpath = outpath.unwrap_or(inpath);
    let casreps = util::get_reports(inpath)?;
    let len = casreps.len();
    if len < 2 {
        bail!("{} reports, nothing to cluster...", len);
    }

    // Get casreps with stacktraces and crashlines
    let (casreps, badreports) = util::reports_from_paths(&casreps, jobs);

    // Handle bad reports
    if !badreports.is_empty() {
        util::save_reports(
            &badreports,
            format!("{}/clerr", &outpath.display()).as_str(),
        )?;
    }

    if casreps.len() < 2 {
        bail!("{} valid reports, nothing to cluster...", casreps.len());
    }

    // Get clusters
    let (clusters, before, after) = Cluster::cluster_reports(&casreps, 0, dedup)?;
    // Save clusters
    util::save_clusters(&clusters, outpath)?;

    Ok((clusters.len(), before, after))
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
            "Error occurred while opening directory with CASR reports. File: {}",
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

    if before != 0 && after == 0 {
        bail!("All {} CASR reports are corrupted", before);
    }

    Ok((before, after))
}

/// Merge unique reports from `input` directory into `output` directory.
/// If `diff` directory is set, unique (`input` \ `output`) reports are saved
/// in `diff` directory.
///
/// # Arguments
///
/// * `input` - path to directory with new CASR reports
///
/// * `output` - path to output directory with CASR reports
///
/// * `diff` - optional: path to save unique (`input` \ `output`) reports
///
/// # Return value
///
/// Number of merged reports
fn merge_or_diff(input: &Path, output: &Path, diff: Option<&Path>) -> Result<u64> {
    let dir = fs::read_dir(output).with_context(|| {
        format!(
            "Error occurred while opening directory with CASR reports. Directory: {}",
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
            "Error occurred while opening directory with CASR reports. Directory: {}",
            input.display()
        )
    })?;

    let save_dir = if let Some(diff) = diff {
        fs::create_dir_all(diff)?;
        diff
    } else {
        output
    };

    let mut new: u64 = 0;
    for entry in dir.flatten() {
        if entry.path().extension().is_some() && entry.path().extension().unwrap() == "casrep" {
            if let Ok(trace) = stacktrace(entry.path().as_path()) {
                if mainhash.insert(trace) {
                    let target = Path::new(&save_dir).join(entry.file_name());
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

/// Add new reports to existing clustering structure
///
/// # Arguments
///
/// * `newpath` - path to directory with new CASR reports
///
/// * `oldpath` - target directory for existing clusters
///
/// * `jobs` - number of jobs for cluster updating process
///
/// * `dedup` - deduplicate casrep by crashline for each cluster, if true
///
/// # Return value
///
/// * Number of casreps added to old clusters
/// * Number of duplicates
/// * Number of casreps deduplicated by crashline
/// * Number of new clusters
/// * Number of valid casreps before crashline deduplication in new clusters
/// * Number of valid casreps after crashline deduplication in new clusters
fn update_clusters(
    newpath: &Path,
    oldpath: &Path,
    jobs: usize,
    dedup: bool,
) -> Result<(usize, usize, usize, usize, usize, usize)> {
    // Get new casreps
    let casreps = util::get_reports(newpath)?;
    let (casreps, _) = util::reports_from_paths(&casreps, jobs);

    // Get casreps from existing clusters
    let mut dirs: Vec<PathBuf> = fs::read_dir(oldpath)
        .unwrap()
        .map(|path| path.unwrap().path())
        .filter(|path| {
            let name = path.file_name().unwrap().to_str().unwrap();
            name.starts_with("cl") && !name.starts_with("clerr")
        })
        .collect();
    dirs.sort();

    // Max cluster number
    let mut max = 0usize;
    // Init clusters vector
    let mut clusters: HashMap<usize, Cluster> = HashMap::new();
    // Init cluster paths vector
    let mut paths: HashMap<usize, &PathBuf> = HashMap::new();
    // Get casreps from each existing cluster
    for dir in &dirs {
        // Get cluster
        let cluster = util::load_cluster(dir, jobs)?;
        // Update max cluster number
        max = max.max(cluster.number);
        // Add cluster path
        paths.insert(cluster.number, dir);
        // Fill cluster info structures
        clusters.insert(cluster.number, cluster);
    }

    // Init list of casreps, which aren't suitable for any cluster
    let mut deviants: Vec<ReportInfo> = Vec::new();
    // Init added casreps counter
    let mut added = 0usize;
    // Init duplicates counter
    let mut duplicates = 0usize;
    // Init crashline duplicates counter
    let mut deduplicated = 0usize;
    // Try to insert each new casrep
    for (casrep, (stacktrace, crashline)) in casreps {
        // list of "inner" clusters for casrep
        let mut inners: Vec<(usize, f64)> = Vec::new();
        // Checker if casrep is duplicate of someone else
        let mut dup = false;
        for cluster in clusters.values_mut() {
            let relation = cluster.relation(&stacktrace);
            match relation {
                Relation::Dup => {
                    dup = true;
                    duplicates += 1;
                    break;
                }
                Relation::Inner(measure) => {
                    inners.push((cluster.number, measure));
                }
                Relation::Outer => {
                    continue;
                }
            }
        }
        // Get cluster with min measure, a.k.a. "closest" one
        let number = if dup {
            continue;
        } else if !inners.is_empty() {
            inners.iter().min_by(|a, b| a.1.total_cmp(&b.1)).unwrap().0
        } else {
            // Outer
            deviants.push((casrep, (stacktrace.to_vec(), crashline.to_string())));
            continue;
        };

        // Update cluster (and dedup crashline)
        if !clusters.get_mut(&number).unwrap().insert(
            casrep.to_path_buf(),
            stacktrace.to_vec(),
            crashline.to_string(),
            dedup,
        ) {
            deduplicated += 1;
            continue;
        }

        // Save casrep
        added += 1;
        fs::copy(
            &casrep,
            format!(
                "{}/{}",
                &paths.get(&number).unwrap().display(),
                &casrep.file_name().unwrap().to_str().unwrap()
            ),
        )?;
    }

    // Handle deviant casreps
    let (result, before, after) = if !deviants.is_empty() {
        let (moved, removed, result, before, after) =
            hierarchical_accumulation(clusters, deviants, max, oldpath, dedup)?;
        // Adjust stat
        added += moved;
        deduplicated += removed;
        (result, before, after)
    } else {
        (0, 0, 0)
    };
    Ok((added, duplicates, deduplicated, result, before, after))
}

/// Perform CASR report accumulation to old clusters using hierarchical clustering
///
/// # Arguments
///
/// * `olds` - list of old clusters represented as `HashMap` of `Cluster`
///
/// * `deviants` - list of deviant reports represented as `Vec` of `ReportInfo`
///
/// * `max` - old clusters max number
///
/// * `dir` - out directory
///
/// * `dedup` - deduplicate crashline, if true
///
/// # Return value
///
/// * Number of moved to old clusters CASR reports
/// * Number of removed from old clusters by crashline deduplication CASR reports
/// * Number of new clusters
/// * Number of valid casreps before crashline deduplication in new clusters
/// * Number of valid casreps after crashline deduplication in new clusters
fn hierarchical_accumulation(
    mut olds: HashMap<usize, Cluster>,
    deviants: Vec<ReportInfo>,
    max: usize,
    dir: &Path,
    dedup: bool,
) -> Result<(usize, usize, usize, usize, usize)> {
    let mut moved = 0usize;
    let mut removed = 0usize;
    let mut before = 0usize;
    let mut deduplicated = 0usize;
    // Forming condensed dissimilarity matrix
    let mut matrix = vec![];
    let keys: Vec<_> = olds.keys().collect();
    let clusters: Vec<_> = olds.values().collect();
    for i in 0..clusters.len() {
        // Write cluster-cluster dist
        for j in i + 1..clusters.len() {
            matrix.push(Cluster::dist(clusters[i], clusters[j]));
        }
        // Write cluster-report dist
        for deviant in &deviants {
            matrix.push(Cluster::dist_rep(clusters[i], deviant));
        }
    }
    // Write report-report dist
    for i in 0..deviants.len() {
        let (_, (stacktrace1, _)) = &deviants[i];
        for deviant2 in deviants.iter().skip(i + 1) {
            let (_, (stacktrace2, _)) = &deviant2;
            matrix.push(1.0 - similarity(stacktrace1, stacktrace2));
        }
    }

    // Clustering
    let res = cluster(matrix, clusters.len() + deviants.len())?;

    // Sync real cluster numbers with resulting numbers
    let mut numbers: HashMap<usize, usize> = HashMap::new();
    for i in 0..clusters.len() {
        numbers.insert(res[i], *keys[i]);
    }
    // New clusters
    let mut news: HashMap<usize, Cluster> = HashMap::new();
    let mut new_num = max;
    for &num in res.iter().skip(clusters.len()) {
        if numbers.contains_key(&num) {
            continue;
        }
        new_num += 1;
        numbers.insert(num, new_num);
        // Create new cluster
        let new = Cluster::new(new_num, vec![], vec![], vec![]);
        news.insert(new_num, new);
    }

    // Save reports
    for i in 0..deviants.len() {
        // Get cluster number
        let number = *numbers.get(&res[i + olds.len()]).unwrap();
        // NOTE: We need not to track stacktraces
        let (casrep, (_, crashline)) = &deviants[i];
        if number > max {
            // New cluster
            before += 1;
            let cluster = news.get_mut(&number).unwrap();
            if !cluster.insert(casrep.to_path_buf(), vec![], crashline.to_string(), dedup) {
                deduplicated += 1;
                continue;
            }
        } else {
            // Old cluster
            let cluster = olds.get_mut(&number).unwrap();
            if !cluster.insert(casrep.to_path_buf(), vec![], crashline.to_string(), dedup) {
                removed += 1;
                continue;
            }
            // Save report
            moved += 1;
            fs::copy(
                casrep,
                format!(
                    "{}/cl{}/{}",
                    &dir.display(),
                    cluster.number,
                    &casrep.file_name().unwrap().to_str().unwrap()
                ),
            )?;
        }
    }
    util::save_clusters(&news, dir)?;
    Ok((moved, removed, news.len(), before, before - deduplicated))
}

/// Calculate silhouette coefficient
///
/// # Arguments
///
/// * `dir` - path to directory with CASR report clusters
///
/// * `jobs` - number of jobs for calculating process
///
/// # Return value
///
/// Silhouette coefficient
fn calc_avg_sil(dir: &Path, jobs: usize) -> Result<f64> {
    // Get cluster dirs
    let mut dirs: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|path| path.unwrap().path())
        .filter(|path| {
            let name = path.file_name().unwrap().to_str().unwrap();
            name.starts_with("cl") && !name.starts_with("clerr")
        })
        .collect();
    dirs.sort();

    if dirs.len() < 2 {
        bail!("{} valid cluster, nothing to calculate...", dirs.len());
    }

    // Init clusters vector
    let mut clusters: Vec<Vec<Stacktrace>> = Vec::new();
    // Init casreps number counter
    let mut size = 0usize;
    // Get casreps from each cluster
    for dir in &dirs {
        // Get casreps from cluster
        let casreps = util::get_reports(dir)?;
        // Get stacktraces from cluster
        let (casreps, _) = util::reports_from_paths(&casreps, jobs);
        let (_, (stacktraces, _)): (Vec<_>, (Vec<_>, Vec<_>)) = casreps.iter().cloned().unzip();
        // Update size
        size += stacktraces.len();
        // Add stacktraces
        clusters.push(stacktraces);
    }
    if size == 0 {
        bail!("{} valid reports, nothing to calculate...", size);
    }
    let avg_sil = avg_sil_coef(&clusters, size);
    Ok(avg_sil)
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
            Arg::new("unique-crashline")
                .long("unique-crashline")
                .env("CASR_CLUSTER_UNIQUE_CRASHLINE")
                .action(ArgAction::SetTrue)
                .value_parser(FalseyValueParser::new())
                .help("Leave reports with unique crash lines in each cluster")
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
            Arg::new("update")
                .short('u')
                .long("update")
                .action(ArgAction::Set)
                .num_args(2)
                .value_parser(clap::value_parser!(PathBuf))
                .value_names(["NEW_DIR", "OLD_DIR"])
                .help(
                    "Update clusters in OLD_DIR using CASR reports from NEW_DIR",
                ),
        )
        .arg(
            Arg::new("estimate")
                .short('e')
                .long("estimate")
                .value_name("DIR")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .help("Calculate silhouette score for clustering results"),
        )
        .arg(
            Arg::new("diff")
                .long("diff")
                .action(ArgAction::Set)
                .num_args(3)
                .value_parser(clap::value_parser!(PathBuf))
                .value_names(["NEW_DIR", "PREV_DIR", "DIFF_DIR"])
                .help(
                    "Compute report sets difference NEW_DIR \\ PREV_DIR. \
                    Copy new CASR reports from NEW_DIR into DIFF_DIR.",
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
    init_ignored_frames!("cpp", "rust", "python", "go", "java", "js", "csharp");

    // Get number of threads
    let jobs = if let Some(jobs) = matches.get_one::<u32>("jobs") {
        *jobs as usize
    } else {
        std::cmp::max(1, num_cpus::get() / 2)
    };

    // Get ignore path
    if let Some(path) = matches.get_one::<PathBuf>("ignore") {
        util::add_custom_ignored_frames(path)?;
    }

    // Get env var
    let dedup_crashlines = matches.get_flag("unique-crashline");

    if matches.contains_id("similarity") {
        let casreps: Vec<&PathBuf> = matches.get_many::<PathBuf>("similarity").unwrap().collect();
        println!(
            "{0:.5}",
            similarity(&stacktrace(casreps[0])?, &stacktrace(casreps[1])?)
        );
    } else if matches.contains_id("clustering") {
        let paths: Vec<&PathBuf> = matches.get_many::<PathBuf>("clustering").unwrap().collect();

        let (result, before, after) = make_clusters(
            paths[0],
            paths.get(1).map(|x| x.as_path()),
            jobs,
            dedup_crashlines,
        )?;
        println!("Number of clusters: {result}");
        // Print crashline dedup summary
        if before != after {
            println!("Number of reports before crashline deduplication: {before}");
            println!("Number of reports after crashline deduplication: {after}");
        }
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
        let new = merge_or_diff(paths[0], paths[1], None)?;
        println!(
            "Merged {} new reports into {} directory",
            new,
            paths[1].display()
        );
    } else if matches.contains_id("update") {
        let paths: Vec<&PathBuf> = matches.get_many::<PathBuf>("update").unwrap().collect();

        let (added, duplicates, deduplicated, result, before, after) =
            update_clusters(paths[0], paths[1], jobs, dedup_crashlines)?;
        println!("Number of casreps added to old clusters: {added}");
        println!("Number of duplicates: {duplicates}");
        if deduplicated != 0 {
            println!("Number of casreps deduplicated by crashline: {deduplicated}");
        }
        if result != 0 {
            println!("Number of new clusters: {result}");
        }
        // Print crashline dedup summary
        if dedup_crashlines {
            println!("Number of reports before crashline deduplication in new clusters: {before}");
            println!("Number of reports after crashline deduplication in new clusters: {after}");
        } else {
            println!("Number of reports in new clusters: {after}");
        }
        let sil = calc_avg_sil(paths[1], jobs)?;
        println!("Cluster silhouette score: {sil}");
    } else if matches.contains_id("estimate") {
        let path: &PathBuf = matches.get_one::<PathBuf>("estimate").unwrap();
        let sil = calc_avg_sil(path, jobs)?;
        println!("Cluster silhouette score: {sil}");
    } else if matches.contains_id("diff") {
        let paths: Vec<&PathBuf> = matches.get_many::<PathBuf>("diff").unwrap().collect();
        let new = merge_or_diff(paths[0], paths[1], Some(paths[2]))?;
        println!(
            "Diff of {} new reports is saved into {} directory",
            new,
            paths[2].display()
        );
    }

    Ok(())
}
