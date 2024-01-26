//! Common utility functions.
extern crate libcasr;

use libcasr::cluster::{Cluster, ReportInfo};
use libcasr::report::CrashReport;
use libcasr::stacktrace::{
    STACK_FRAME_FILEPATH_IGNORE_REGEXES, STACK_FRAME_FUNCTION_IGNORE_REGEXES,
};

use anyhow::{bail, Context, Result};
use clap::ArgMatches;
use is_executable::IsExecutable;
use log::{info, warn};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use simplelog::*;
use wait_timeout::ChildExt;

use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::RwLock;
use std::time::Duration;

/// Call casr-san with the provided options
///
/// # Arguments
///
/// * `matches` - casr options
///
/// * `name` - main tool name, that called sub tool
///
/// * `argv` - executable file options
pub fn call_casr_san(matches: &ArgMatches, argv: &[&str], name: &str) -> Result<()> {
    let tool = get_path("casr-san")?;
    let mut cmd = Command::new(&tool);
    if let Some(report_path) = matches.get_one::<PathBuf>("output") {
        cmd.args(["--output", report_path.to_str().unwrap()]);
    } else {
        cmd.args(["--stdout"]);
    }
    if let Some(path) = matches.get_one::<PathBuf>("stdin") {
        cmd.args(["--stdin", path.to_str().unwrap()]);
    }
    if let Some(path) = matches.get_one::<String>("ignore") {
        cmd.args(["--ignore", path]);
    }
    cmd.arg("--").args(argv);

    let output = cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .with_context(|| format!("Couldn't launch {cmd:?}"))?;

    if output.status.success() {
        Ok(())
    } else {
        bail!("{tool:?} error when calling from {name}");
    }
}

/// Save a report to the specified path
///
/// # Arguments
///
/// * `report` - output report
///
/// * `matches` - casr options
///
/// * `argv` - executable file options
pub fn output_report(report: &CrashReport, matches: &ArgMatches, argv: &[&str]) -> Result<()> {
    // Convert report to string.
    let repstr = serde_json::to_string_pretty(&report).unwrap();

    if matches.contains_id("stdout") && matches.get_flag("stdout") {
        println!("{repstr}\n");
    }

    if let Some(report_path) = matches.get_one::<PathBuf>("output") {
        let mut report_path = report_path.clone();
        if report_path.is_dir() {
            let executable_name = PathBuf::from(&argv[0]);
            let file_name = match argv.iter().skip(1).find(|&x| Path::new(&x).exists()) {
                Some(x) => match Path::new(x).file_stem() {
                    Some(file) => file.to_os_string().into_string().unwrap(),
                    None => x.to_string(),
                },
                None => report.date.clone(),
            };
            report_path.push(format!(
                "{}_{}.casrep",
                executable_name
                    .as_path()
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap(),
                file_name
            ));
        }
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&report_path)
        {
            file.write_all(repstr.as_bytes()).with_context(|| {
                format!(
                    "Couldn't write data to report file `{}`",
                    report_path.display()
                )
            })?;
        } else {
            bail!("Couldn't save report to file: {}", report_path.display());
        }
    }
    Ok(())
}

/// Add custom regex for frames from user that should be ignored during analysis
///
/// # Arguments
///
/// * `path` - path to the specification file
pub fn add_custom_ignored_frames(path: &Path) -> Result<()> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Cannot open file: {}", path.display()))?;
    let mut reader = BufReader::new(file)
        .lines()
        .map(|x| x.unwrap())
        .collect::<Vec<String>>();
    if reader.is_empty() || !reader[0].contains("FUNCTIONS") && !reader[0].contains("FILES") {
        bail!(
            "File {} is empty or does not contain \
                    FUNCTIONS or FILES on the first line",
            path.display()
        );
    }
    let (funcs, paths) = if reader[0].contains("FUNCTIONS") {
        if let Some(bound) = reader.iter().position(|x| x.contains("FILES")) {
            let files = reader.split_off(bound);
            (reader, files)
        } else {
            (reader, vec![])
        }
    } else if let Some(bound) = reader.iter().position(|x| x.contains("FUNCTIONS")) {
        let funcs = reader.split_off(bound);
        (funcs, reader)
    } else {
        (vec![], reader)
    };
    STACK_FRAME_FUNCTION_IGNORE_REGEXES
        .write()
        .unwrap()
        .extend_from_slice(&funcs);
    STACK_FRAME_FILEPATH_IGNORE_REGEXES
        .write()
        .unwrap()
        .extend_from_slice(&paths);
    Ok(())
}

/// Check if stdin is set
///
/// # Arguments
///
/// * `matches` - command line arguments
///
/// # Return value
///
/// Path to file with stdin
pub fn stdin_from_matches(matches: &ArgMatches) -> Result<Option<PathBuf>> {
    if let Some(file) = matches.get_one::<PathBuf>("stdin") {
        if file.exists() {
            Ok(Some(file.to_owned()))
        } else {
            bail!("Stdin file not found: {}", file.display());
        }
    } else {
        Ok(None)
    }
}

/// Initialize logging with level from command line arguments (debug or info).
pub fn initialize_logging(matches: &ArgMatches) {
    let log_level = if matches.get_one::<String>("log-level").unwrap() == "debug" {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    let _ = TermLogger::init(
        log_level,
        ConfigBuilder::new()
            .set_time_offset_to_local()
            .unwrap()
            .build(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    );
}

/// Parse CASR report from file.
///
/// # Arguments
///
/// * `path` - path to CASR report.
pub fn report_from_file(path: &Path) -> Result<CrashReport> {
    let Ok(file) = std::fs::File::open(path) else {
        bail!("Error with opening Casr report: {}", path.display());
    };
    let report: Result<CrashReport, _> = serde_json::from_reader(BufReader::new(file));
    if let Err(e) = report {
        bail!("Error with parsing JSON {}: {}", path.display(), e);
    }
    Ok(report.unwrap())
}

/// Function logs progress
///
/// # Arguments
///
/// * `processed_items` - current number of processed elements
///
/// * `total` - total number of elements
pub fn log_progress(processed_items: &RwLock<usize>, total: usize) {
    let mut cnt = 0;

    loop {
        let current = *processed_items.read().unwrap();

        if current == total {
            return;
        }

        if current > 0 && current > cnt {
            info!("Progress: {}/{}", current, total);
        }
        cnt = current;
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
}

/// Get output of target command with specified timeout
///
/// # Arguments
///
/// * `command` - target command with args
///
/// * `timeout` - target command timeout (in seconds)
///
/// * `error_on_timeout` - throw an error if timeout happens
///
/// # Return value
///
/// Command output
pub fn get_output(command: &mut Command, timeout: u64, error_on_timeout: bool) -> Result<Output> {
    // If timeout is specified, spawn and check timeout
    // Else get output
    if timeout != 0 {
        let mut child = command
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .with_context(|| "Failed to start command: {command:?}")?;
        if child
            .wait_timeout(Duration::from_secs(timeout))
            .unwrap()
            .is_none()
        {
            let _ = child.kill();
            if error_on_timeout {
                bail!("Timeout: {:?}", command);
            } else {
                warn!("Timeout: {:?}", command);
            }
        }
        Ok(child.wait_with_output()?)
    } else {
        command
            .output()
            .with_context(|| format!("Couldn't launch {command:?}"))
    }
}

/// Get Atheris asan_with_fuzzer library path.
pub fn get_atheris_lib() -> Result<String> {
    let mut cmd = Command::new("python3");
    cmd.arg("-c")
        .arg("import atheris; print(atheris.path(), end='')")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = cmd
        .output()
        .with_context(|| format!("Couldn't launch {cmd:?}"))?;
    let out = String::from_utf8_lossy(&output.stdout);
    let err = String::from_utf8_lossy(&output.stderr);
    if !err.is_empty() {
        bail!("Failed to get Atheris path: {}", err);
    }
    Ok(format!("{out}/asan_with_fuzzer.so"))
}

/// Create output, timeout and oom directories
///
/// # Arguments
///
/// * `matches` - tool arguments
///
/// # Return value
///
/// Path to output directory
pub fn initialize_dirs(matches: &clap::ArgMatches) -> Result<&PathBuf> {
    // Get output dir
    let output_dir = matches.get_one::<PathBuf>("output").unwrap();
    if !output_dir.exists() {
        fs::create_dir_all(output_dir).with_context(|| {
            format!("Couldn't create output directory {}", output_dir.display())
        })?;
    } else if output_dir.read_dir()?.next().is_some() {
        if matches.get_flag("force-remove") {
            fs::remove_dir_all(output_dir)?;
            fs::create_dir_all(output_dir).with_context(|| {
                format!("Couldn't create output directory {}", output_dir.display())
            })?;
        } else {
            bail!("Output directory is not empty.");
        }
    }
    // Get oom dir
    let oom_dir = output_dir.join("oom");
    if fs::create_dir_all(&oom_dir).is_err() {
        bail!("Failed to create dir {}", &oom_dir.to_str().unwrap());
    }
    // Get timeout dir
    let timeout_dir = output_dir.join("timeout");
    if fs::create_dir_all(&timeout_dir).is_err() {
        bail!("Failed to create dir {}", &timeout_dir.to_str().unwrap());
    }

    Ok(output_dir)
}

/// Method checks whether binary file contains predefined symbols.
///
/// # Arguments
///
/// * `path` - path to binary to check.
///
/// # Return value
///
/// Set of important symbols
pub fn symbols_list(path: &Path) -> Result<HashSet<&str>> {
    let mut found_symbols = HashSet::new();
    if let Ok(buffer) = fs::read(path) {
        if let Ok(elf) = goblin::elf::Elf::parse(&buffer) {
            let symbols = [
                "__asan",
                "__ubsan",
                "__tsan",
                "__msan",
                "__llvm_profile",
                "runtime.go",
            ];
            for sym in elf.syms.iter() {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    for symbol in symbols.iter() {
                        if name.contains(symbol) {
                            found_symbols.insert(*symbol);
                            break;
                        }
                    }
                }
            }
        } else {
            bail!("Fuzz target: {} must be an ELF executable.", path.display());
        }
    } else {
        bail!("Couldn't read fuzz target binary: {}.", path.display());
    }

    Ok(found_symbols)
}

/// Function searches for path to the tool
///
/// # Arguments
///
/// * 'tool' - tool name
///
/// # Return value
///
/// Path to the tool
pub fn get_path(tool: &str) -> Result<PathBuf> {
    let mut path_to_tool = std::env::current_exe()?;
    let current_tool = path_to_tool
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    path_to_tool.pop();
    path_to_tool.push(tool);
    if path_to_tool.is_executable() {
        Ok(path_to_tool)
    } else if let Ok(path_to_tool) = which::which(tool) {
        Ok(path_to_tool)
    } else {
        bail!(
            "{path_to_tool:?}: No {tool} next to {current_tool}. And there is no {tool} in PATH."
        );
    }
}

/// Get CASR reports from specified directory
///
/// # Arguments
///
/// * `dir` - directory path
///
/// # Return value
///
/// A vector of reports paths
pub fn get_reports(dir: &Path) -> Result<Vec<PathBuf>> {
    let dir = fs::read_dir(dir).with_context(|| format!("File: {}", dir.display()))?;
    let casreps: Vec<PathBuf> = dir
        .map(|path| path.unwrap().path())
        .filter(|s| s.extension().is_some() && s.extension().unwrap() == "casrep")
        .collect();
    Ok(casreps)
}

/// Parse CASR reports from specified paths.
///
/// # Arguments
///
/// * `casreps` - a vector of report paths
///
/// * `jobs` - number of jobs for parsing process
///
/// # Return value
///
/// * A vector of correctly parsed report info: paths, stacktraces and crashlines
/// * A vector of bad reports
pub fn reports_from_paths(casreps: Vec<PathBuf>, jobs: usize) -> (Vec<ReportInfo>, Vec<PathBuf>) {
    // Get len
    let len = casreps.len();
    // Start thread pool.
    let custom_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(jobs.min(len))
        .build()
        .unwrap();
    // Report info from casreps: (casrep, (trace, crashline))
    let mut casrep_info: RwLock<Vec<ReportInfo>> = RwLock::new(Vec::new());
    // Casreps with stacktraces, that we cannot parse
    let mut badreports: RwLock<Vec<PathBuf>> = RwLock::new(Vec::new());
    custom_pool.install(|| {
        (0..len).into_par_iter().for_each(|i| {
            if let Ok(report) = report_from_file(casreps[i].as_path()) {
                if let Ok(trace) = report.filtered_stacktrace() {
                    casrep_info
                        .write()
                        .unwrap()
                        .push((casreps[i].clone(), (trace, report.crashline)));
                } else {
                    badreports.write().unwrap().push(casreps[i].clone());
                }
            } else {
                badreports.write().unwrap().push(casreps[i].clone());
            }
        })
    });
    let casrep_info = casrep_info.get_mut().unwrap();
    let badreports = badreports.get_mut().unwrap().to_vec();
    // Sort by casrep filename
    casrep_info.sort_by(|a, b| {
        a.0.file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .cmp(b.0.file_name().unwrap().to_str().unwrap())
    });

    (casrep_info.to_vec(), badreports)
}

/// Get `Cluster` structure from specified directory path.
///
/// # Arguments
///
/// * `dir` - valid cluster dir path
///
/// * `jobs` - number of jobs for parsing process
///
/// # Return value
///
/// `Cluster` structure
pub fn cluster_from_dir(dir: &Path, jobs: usize) -> Result<Cluster> {
    // Get cluster number
    let i = dir.file_name().unwrap().to_str().unwrap()[2..]
        .to_string()
        .parse::<usize>()
        .unwrap();
    // Get casreps from cluster
    let casreps = get_reports(dir)?;
    let (casreps, _) = reports_from_paths(casreps, jobs);
    let (_, (stacktraces, crashlines)): (Vec<_>, (Vec<_>, Vec<_>)) =
        casreps.iter().cloned().unzip();
    // Create cluster
    // NOTE: We don't care about paths of casreps from existing clusters
    Ok(Cluster::new(i, Vec::new(), stacktraces, crashlines))
}

/// Save clusters to given directory
///
/// # Arguments
///
/// * `clusters` - given `Cluster` structures for saving
///
/// * `dir` - out directory
pub fn save_clusters(clusters: &HashMap<usize, Cluster>, dir: &Path) -> Result<()> {
    for cluster in clusters.values() {
        fs::create_dir_all(format!("{}/cl{}", &dir.display(), cluster.number))?;
        for casrep in cluster.paths() {
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
    Ok(())
}

/// Save CASR reports to given directory
///
/// # Arguments
///
/// * `reports` - A vector of CASR reports
///
/// * `dir` - out directory
pub fn save_reports(reports: Vec<PathBuf>, dir: String) -> Result<()> {
    if !Path::new(&dir).exists() {
        fs::create_dir_all(&dir)?;
    }
    for report in reports {
        fs::copy(
            &report,
            format!("{}/{}", dir, &report.file_name().unwrap().to_str().unwrap()),
        )?;
    }
    Ok(())
}
