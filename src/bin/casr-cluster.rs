extern crate anyhow;
extern crate casr;
extern crate clap;
extern crate gdb_command;
extern crate num_cpus;
extern crate rayon;
extern crate regex;
extern crate serde_json;

use casr::asan::AsanStacktrace;
use casr::constants::*;
use casr::gdb::GdbStacktrace;
use casr::init_ignored_frames;
use casr::python::PythonStacktrace;
use casr::stacktrace::*;
use casr::util;

use anyhow::{bail, Context, Result};
use clap::{App, Arg};
use gdb_command::mappings::*;
use gdb_command::stacktrace::*;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use regex::Regex;

use std::collections::HashSet;
use std::fs;
use std::io::BufReader;
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
    // Opening file and reading it
    let file = std::fs::File::open(path);
    if file.is_err() {
        bail!("Error with opening Casr report: {}", path.display());
    }
    let file = file.unwrap();
    let reader = BufReader::new(file);

    let u = serde_json::from_reader(reader);
    if u.is_err() {
        bail!("Json parse error. File: {}", path.display());
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

            let mut rawtrace: Stacktrace = Default::default();
            if let Some(array) = u.get("AsanReport") {
                if let Some(array) = array.as_array() {
                    if !array.is_empty() {
                        rawtrace = AsanStacktrace::parse_stacktrace(&trace)
                            .with_context(|| format!("File: {}", path.display()))?;
                    }
                } else {
                    bail!("Error while parsing AsanReport. File: {}", path.display());
                }
            }

            if let Some(array) = u.get("PythonReport") {
                if let Some(array) = array.as_array() {
                    if !array.is_empty() {
                        rawtrace = PythonStacktrace::parse_stacktrace(&trace)
                            .with_context(|| format!("File: {}", path.display()))?;
                    }
                } else {
                    bail!("Error while parsing PythonReport. File: {}", path.display());
                }
            }

            if rawtrace.is_empty() {
                rawtrace = GdbStacktrace::parse_stacktrace(&trace)
                    .with_context(|| format!("File: {}", path.display()))?;
            };

            // For libfuzzer: delete functions below LLVMFuzzerTestOneInput
            if let Some(pos) = &rawtrace
                .iter()
                .position(|x| x.function.contains("LLVMFuzzerTestOneInput"))
            {
                rawtrace.drain(pos + 1..);
            }

            if rawtrace.is_empty() {
                bail!("Current stack trace length is null".to_string());
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
                        let mappings = MappedFiles::from_gdb(trace)
                            .with_context(|| format!("File: {}", path.display()))?;
                        rawtrace.compute_module_offsets(&mappings);
                    }
                }
            }

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

            // Remove trusted functions from stack trace
            let pos = rawtrace.iter().position(|entry| {
                (entry.function.is_empty() || !rfunction.is_match(&entry.function))
                    && (entry.module.is_empty() || !rfile.is_match(&entry.module))
                    && (entry.debug.file.is_empty() || !rfile.is_match(&entry.debug.file))
            });
            if let Some(pos) = pos {
                rawtrace.drain(0..pos);
            }

            return Ok(rawtrace);
        }
    }
    bail!("Json parse error, file: {}", path.display());
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
pub fn make_clusters(inpath: &Path, outpath: Option<&Path>, jobs: usize) -> Result<u32> {
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
    rayon::ThreadPoolBuilder::new()
        .num_threads(jobs.min(len))
        .build_global()
        .unwrap();

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
fn deduplication(indir: &Path, outdir: Option<PathBuf>) -> Result<(usize, usize)> {
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
    let mut badrepidxs: Vec<usize> = Vec::new();
    let mut stacktraces: Vec<Stacktrace> = Vec::new();
    for (index, report) in paths.iter().enumerate() {
        if let Ok(trace) = stacktrace(report.as_path()) {
            stacktraces.push(trace);
        } else {
            badrepidxs.push(index);
        }
    }

    let result = dedup_stacktraces(&stacktraces);

    if let Some(ref outdir) = outdir {
        fs::create_dir_all(outdir)?;
        (0..paths.len())
            .filter(|x| !badrepidxs.contains(x))
            .enumerate()
            .try_for_each(|(res_idx, true_idx)| {
                if result[res_idx].is_some() {
                    fs::copy(
                        &paths[true_idx],
                        Path::new(&outdir).join(paths[true_idx].file_name().unwrap()),
                    )?;
                }
                Ok::<(), anyhow::Error>(())
            })?;
    } else {
        (0..paths.len())
            .filter(|x| !badrepidxs.contains(x))
            .enumerate()
            .try_for_each(|(res_idx, true_idx)| {
                if result[res_idx].is_none() {
                    fs::remove_file(&paths[true_idx])
                } else {
                    Ok(())
                }
            })?;
    }

    if !badrepidxs.is_empty() {
        let clerr = outdir.unwrap_or_else(|| indir.to_path_buf()).join("clerr");
        fs::create_dir_all(&clerr)?;
        for &index in badrepidxs.iter() {
            fs::copy(
                &paths[index],
                clerr.join(paths[index].file_name().unwrap().to_str().unwrap()),
            )?;
        }
    }

    before += paths.len();
    after += result.iter().filter(|x| x.is_some()).count();

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
    let matches = App::new("casr-cluster")
        .version("2.4.0")
        .author(
            "Andrey Fedotov <fedotoff@ispras.ru>, \
            Alexey Vishnyakov <vishnya@ispras.ru>, Georgy Savidov <avgor46@ispras.ru>",
        )
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
                .takes_value(true)
                .min_values(1)
                .max_values(2)
                .value_name("INPUT_DIR> <OUTPUT_DIR")
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
                .takes_value(true)
                .min_values(2)
                .max_values(2)
                .value_names(&["INPUT_DIR", "OUTPUT_DIR"])
                .help(
                    "Merge INPUT_DIR into OUTPUT_DIR. Only new CASR reports from \
                    INPUT_DIR will be added to OUTPUT_DIR.",
                ),
        )
        .arg(
            Arg::new("ignore")
                .long("ignore")
                .takes_value(true)
                .value_name("FILE")
                .help("File with regular expressions for functions and file paths that should be ignored"),
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
    init_ignored_frames!("cpp", "rust", "python");

    if let Some(path) = matches.value_of("ignore") {
        util::add_custom_ignored_frames(Path::new(path))?;
    }
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
            std::cmp::max(1, num_cpus::get() / 2)
        };

        let result = make_clusters(paths[0], paths.get(1).cloned(), jobs)?;
        println!("Number of clusters: {result}");
    } else if matches.is_present("deduplication") {
        let paths: Vec<&Path> = matches
            .values_of("deduplication")
            .unwrap()
            .map(Path::new)
            .collect();
        let (before, after) = deduplication(paths[0], paths.get(1).map(|x| x.to_path_buf()))?;
        println!("Number of reports before deduplication: {before}");
        println!("Number of reports after deduplication: {after}");
    } else if matches.is_present("merge") {
        let paths: Vec<&Path> = matches.values_of("merge").unwrap().map(Path::new).collect();
        let new = merge_dirs(paths[0], paths[1])?;
        println!(
            "Merged {} new reports into {} directory",
            new,
            paths[1].display()
        );
    }

    Ok(())
}
