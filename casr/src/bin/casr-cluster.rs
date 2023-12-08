use casr::util;
use libcasr::{init_ignored_frames, stacktrace::*};

use anyhow::{bail, Context, Result};
use clap::{builder::FalseyValueParser, Arg, ArgAction};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

use std::collections::HashSet;
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
/// * `offset` - cluster enumerate offset
///
/// # Return value
///
/// * Number of clusters
/// * Number of valid casreps before crashiline deduplication
/// * Number of valid casreps after crashiline deduplication
fn make_clusters(
    inpath: &Path,
    outpath: Option<&Path>,
    jobs: usize,
    dedup: bool,
    offset: usize,
) -> Result<(usize, usize, usize)> {
    // if outpath is "None" we consider that outpath and inpath are the same
    let outpath = outpath.unwrap_or(inpath);
    let casreps = util::get_reports(inpath)?;
    let len = casreps.len();
    if len < 2 {
        bail!("{} reports, nothing to cluster...", len);
    }

    // Get casreps with stacktraces and crashlines
    let (casreps, stacktraces, crashlines, badreports) = util::reports_from_dirs(casreps, jobs);

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

    // Get clusters
    let mut clusters = cluster_stacktraces(&stacktraces)?;

    // Cluster formation
    let cluster_cnt: usize = *clusters.iter().max().unwrap();
    for i in 1..=cluster_cnt {
        fs::create_dir_all(format!("{}/cl{}", &outpath.display(), i + offset))?;
    }

    // Init before and after dedup counters
    let before_cnt = casreps.len();
    let mut after_cnt = before_cnt;

    // Get clusters with crashline deduplication
    if dedup {
        after_cnt = dedup_crashlines(&crashlines, &mut clusters);
    }

    for i in 0..clusters.len() {
        // Skip casreps with duplicate crashlines
        if clusters[i] == 0 {
            continue;
        }
        fs::copy(
            &casreps[i],
            format!(
                "{}/cl{}/{}",
                &outpath.display(),
                clusters[i] + offset,
                &casreps[i].file_name().unwrap().to_str().unwrap()
            ),
        )?;
    }
    Ok((cluster_cnt, before_cnt, after_cnt))
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

/// Perform the clustering of casreps
///
/// # Arguments
///
/// * `newpath` - path to directory with new CASR reports
///
/// * `oldpath` - target directory for exiting clusters
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
/// * Number of valid casreps before crashiline deduplication in new clusters
/// * Number of valid casreps after crashiline deduplication in new clusters
fn update_clusters(
    newpath: &Path,
    oldpath: &Path,
    jobs: usize,
    dedup: bool,
    inner_strategy: AccumStrategy,
    outer_strategy: AccumStrategy,
) -> Result<(usize, usize, usize, usize, usize, usize)> {
    // Get new casreps
    let casreps = util::get_reports(newpath)?;
    let (casreps, stacktraces, crashlines, _) = util::reports_from_dirs(casreps, jobs);
    let casreps = casreps
        .iter()
        .zip(stacktraces.iter().zip(crashlines.iter()));

    // Get casreps from existing clusters
    let mut cluster_dirs: Vec<PathBuf> = fs::read_dir(oldpath)
        .unwrap()
        .map(|path| path.unwrap().path())
        .filter(|path| {
            path.clone()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("cl")
        })
        .collect();
    cluster_dirs.sort();
    let len = cluster_dirs.len();
    // Init clusters vector
    let mut clusters: Vec<Cluster> = Vec::new();
    // Init dedup crashline list for each cluster
    let mut unique_crashlines: Vec<HashSet<String>> = vec![HashSet::new(); len];
    // Get casreps from each existing cluster
    for cluster in &cluster_dirs {
        // Get cluster number
        let i = cluster.clone().file_name().unwrap().to_str().unwrap()[2..]
            .to_string()
            .parse::<usize>()
            .unwrap();
        // Get casreps from cluster
        let casreps = util::get_reports(cluster)?;
        let (_, stacktraces, crashlines, _) = util::reports_from_dirs(casreps, jobs);
        // Fill cluster info structures
        clusters.push(Cluster::new(i, stacktraces));
        if dedup {
            for crashline in crashlines {
                // NOTE: Clusters enumerate from 1, not 0
                unique_crashlines[i - 1].insert(crashline);
            }
        }
    }

    // Init list of casreps, which aren't suitable for any cluster
    let mut deviants = Vec::<&PathBuf>::new();
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
        // list of "outer" clusters for casrep
        let mut outers: Vec<(usize, f64)> = Vec::new();
        // Checker if casrep is duplicate of someone else
        let mut dup = false;
        for cluster in &mut clusters {
            let relation = relation(
                stacktrace,
                cluster,
                inner_strategy.clone(),
                outer_strategy.clone(),
            );
            match relation {
                Relation::Dup => {
                    dup = true;
                    duplicates += 1;
                    break;
                }
                Relation::Inner(measure) => {
                    inners.push((cluster.number, measure));
                }
                Relation::Outer(measure) => {
                    outers.push((cluster.number, measure));
                }
                Relation::Oot => {
                    continue;
                }
            }
        }
        // Get cluster with min measure, a.k.a. "closest" one
        let number = if dup {
            continue;
        } else if !inners.is_empty() {
            inners.iter().min_by(|a, b| a.1.total_cmp(&b.1)).unwrap().0
        } else if !outers.is_empty() {
            outers.iter().min_by(|a, b| a.1.total_cmp(&b.1)).unwrap().0
        } else {
            // Out of threshold
            deviants.push(casrep);
            continue;
        };

        // Make crashline deduplication
        if dedup
            && !crashline.is_empty()
            && !unique_crashlines[number - 1].insert(crashline.to_string())
        {
            deduplicated += 1;
            continue;
        }

        // Save casrep
        added += 1;
        fs::copy(
            casrep,
            format!(
                "{}/{}",
                &cluster_dirs[number - 1].display(),
                &casrep.file_name().unwrap().to_str().unwrap()
            ),
        )?;

        // Update cluster
        let i = clusters.iter().position(|a| a.number == number).unwrap();
        clusters[i].push(stacktrace.to_vec());
    }

    // Handle deviant casreps
    let (result, before, after) = if !deviants.is_empty() {
        // Copy casrep to tmp dir
        let deviant_dir = format!("{}/deviant", &oldpath.display());
        fs::create_dir_all(&deviant_dir)?;
        for casrep in deviants {
            fs::copy(
                casrep,
                format!(
                    "{}/{}",
                    &deviant_dir,
                    &casrep.file_name().unwrap().to_str().unwrap()
                ),
            )?;
        }
        // Cluster deviant casreps
        make_clusters(Path::new(&deviant_dir), Some(oldpath), jobs, dedup, len)?
    } else {
        (0, 0, 0)
    };
    Ok((added, duplicates, deduplicated, result, before, after))
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
fn avg_sil(dir: &Path, jobs: usize) -> Result<f64> {
    // Get cluster dirs
    let mut dirs: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|path| path.unwrap().path())
        .filter(|path| {
            path.clone()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("cl")
        })
        .collect();
    dirs.sort();

    if dirs.len() < 2 {
        bail!("{} valid cluster, nothing to calculate...", dirs.len());
    }

    // Init clusters vector
    let mut clusters: Vec<Vec<Stacktrace>> = Vec::new();
    // Init casreps nuber counter
    let mut size = 0usize;
    // Get casreps from each cluster
    for dir in &dirs {
        // Get casreps from cluster
        let casreps = util::get_reports(dir)?;
        // Get stacktraces from cluster
        let (_, stacktraces, _, _) = util::reports_from_dirs(casreps, jobs);
        // Update size
        size += stacktraces.len();
        // Add stacktraces
        clusters.push(stacktraces);
    }
    // Init sil sum
    let mut sum = 0f64;
    // Calculate silhouette coefficient for each casrep
    for i in 0..clusters.len() {
        for num in 0..clusters[i].len() {
            let sil = sil_coef(num, i, &clusters);
            sum += sil;
        }
    }
    Ok(sum / size as f64)
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
                    "Update clusters from OLD_DIR using CASR reports from NEW_DIR.",
                ),
        )
        .arg(
            Arg::new("inner-strategy")
                .long("inner-strategy")
                .value_name("STRATEGY")
                .action(ArgAction::Set)
                .value_parser(["Diam", "Dist"])
                .default_value("Dist")
                .help("Strategy for inner cluster choosing when updating"),
        )
        .arg(
            Arg::new("outer-strategy")
                .long("outer-strategy")
                .value_name("STRATEGY")
                .action(ArgAction::Set)
                .value_parser(["Delta", "Diam", "Dist"])
                .default_value("Dist")
                .help("Strategy for outer cluster choosing when updating"),
        )
        .arg(
            Arg::new("estimate")
                .long("estimate")
                .value_name("DIR")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .help("Make cluster estimation for DIR using silhouette index"),
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

    init_ignored_frames!("cpp", "rust", "python", "go", "java");

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
            0,
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
        let new = merge_dirs(paths[0], paths[1])?;
        println!(
            "Merged {} new reports into {} directory",
            new,
            paths[1].display()
        );
    } else if matches.contains_id("update") {
        let paths: Vec<&PathBuf> = matches.get_many::<PathBuf>("update").unwrap().collect();

        let inner_strategy = matches.get_one::<String>("inner-strategy").unwrap();
        let inner_strategy = match inner_strategy.as_str() {
            "Diam" => AccumStrategy::Diam,
            _ => AccumStrategy::Dist,
        };
        let outer_strategy = matches.get_one::<String>("outer-strategy").unwrap();
        let outer_strategy = match outer_strategy.as_str() {
            "Delta" => AccumStrategy::Delta,
            "Diam" => AccumStrategy::Diam,
            _ => AccumStrategy::Dist,
        };

        let (added, duplicates, deduplicated, result, before, after) = update_clusters(
            paths[0],
            paths[1],
            jobs,
            dedup_crashlines,
            inner_strategy,
            outer_strategy,
        )?;
        println!("Number of casreps added to old clusters: {added}");
        println!("Number of duplicates: {duplicates}");
        if deduplicated != 0 {
            println!("Number of casreps deduplicated by crashline: {deduplicated}");
        }
        if result != 0 {
            println!("Number of new clusters: {result}");
        }
        // Print crashline dedup summary
        if before != after {
            println!("Number of reports before crashline deduplication in new clusters: {before}");
            println!("Number of reports after crashline deduplication in new clusters: {after}");
        }
        let sil = avg_sil(paths[1], jobs)?;
        println!("Cluster silhouette index: {sil}");
    } else if matches.contains_id("estimate") {
        let path: &PathBuf = matches.get_one::<PathBuf>("estimate").unwrap();
        let sil = avg_sil(path, jobs)?;
        println!("Cluster silhouette index: {sil}");
    }

    Ok(())
}
