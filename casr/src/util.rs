//! Common utility functions.
extern crate libcasr;

use libcasr::report::CrashReport;
use libcasr::stacktrace::{
    STACK_FRAME_FILEPATH_IGNORE_REGEXES, STACK_FRAME_FUNCTION_IGNORE_REGEXES,
};

use anyhow::{bail, Context, Result};
use clap::ArgMatches;
use log::{debug, error, info, warn};
use simplelog::*;
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::RwLock;
use std::time::Duration;

use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use wait_timeout::ChildExt;
use walkdir::WalkDir;
use which::which;

/// Call sub tool with the provided options
///
/// # Arguments
///
/// * `matches` - casr options
///
/// * `name` - main tool name, that called sub tool
///
/// * `argv` - executable file options
pub fn call_sub_tool(matches: &ArgMatches, argv: &[&str], name: &str) -> Result<()> {
    let tool = matches.get_one::<PathBuf>("sub-tool").unwrap();
    if which(tool).is_err() {
        if !tool.exists() {
            bail!("Sub tool {tool:?} doesn't exist");
        }
        if !tool.is_file() {
            bail!("Sub tool {tool:?} isn't a file");
        }
        if tool.metadata()?.permissions().mode() & 0o111 == 0 {
            bail!("Sub tool {tool:?} isn't executable");
        }
    }
    let mut cmd = Command::new(tool);
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

/// Create output, timeout and oom directories
///
/// # Arguments
///
/// `matches` - tool argumnets
///
/// Return value
///
/// Paths to (output, oom, timeout) directories
fn initialize_dirs(matches: &clap::ArgMatches) -> Result<(&PathBuf, PathBuf, PathBuf)> {
    // Get output dir
    let output_dir = matches.get_one::<PathBuf>("output").unwrap();
    if !output_dir.exists() {
        fs::create_dir_all(output_dir).with_context(|| {
            format!("Couldn't create output directory {}", output_dir.display())
        })?;
    } else if output_dir.read_dir()?.next().is_some() {
        bail!("Output directory is not empty.");
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

    Ok((output_dir, oom_dir, timeout_dir))
}

#[derive(Debug, Clone, Default)]
/// Information about crash to reproduce it.
pub struct CrashInfo {
    /// Path to crash input.
    pub path: PathBuf,
    /// Target command line args.
    pub target_args: Vec<String>,
    /// Input file argument index starting from argv\[1\], None for stdin.
    pub at_index: Option<usize>,
    /// ASAN.
    pub is_asan: bool,
}

impl<'a> CrashInfo {
    /// Generate Casr report for crash.
    ///
    /// # Arguments
    ///
    /// * `tool` - tool that generates reports
    ///
    /// * `output_dir` - save report to specified directory or use the same directory as crash
    ///
    /// * `timeout` - target program timeout (in seconds)
    ///
    /// *  `envs` - environment variables for target
    pub fn run_casr<T: Into<Option<&'a Path>>>(
        &self,
        tool: &str,
        output_dir: T,
        timeout: u64,
        envs: &HashMap<String, String>,
    ) -> Result<()> {
        let mut args: Vec<String> = vec!["-o".to_string()];
        let (report_path, output_dir) = if let Some(out) = output_dir.into() {
            (out.join(self.path.file_name().unwrap()), out)
        } else {
            (self.path.clone(), self.path.parent().unwrap())
        };
        if self.is_asan {
            args.push(format!("{}.casrep", report_path.display()));
        } else {
            args.push(format!("{}.gdb.casrep", report_path.display()));
        }

        args.push("--".to_string());
        args.extend_from_slice(&self.target_args);
        if let Some(at_index) = self.at_index {
            let input = args[at_index + 3].replace("@@", self.path.to_str().unwrap());
            args[at_index + 3] = input;
        }
        if tool.eq("casr-python") {
            args.insert(3, "python3".to_string());
        }
        if self.at_index.is_none() {
            args.insert(0, self.path.to_str().unwrap().to_string());
            args.insert(0, "--stdin".to_string());
        }
        if timeout != 0 {
            args.insert(0, timeout.to_string());
            args.insert(0, "-t".to_string());
        }

        let tool = if self.is_asan { tool } else { "casr-gdb" };
        let mut casr_cmd = Command::new(tool);
        casr_cmd.args(&args);
        casr_cmd.envs(envs);

        debug!("{:?}", casr_cmd);

        // Get output
        let casr_output = casr_cmd
            .output()
            .with_context(|| format!("Couldn't launch {casr_cmd:?}"))?;

        if !casr_output.status.success() {
            let err = String::from_utf8_lossy(&casr_output.stderr);
            if err.contains("Timeout") {
                let mut timeout_name = self
                    .path
                    .file_name()
                    .unwrap()
                    .to_os_string()
                    .into_string()
                    .unwrap();
                if let Some(idx) = timeout_name.find('-') {
                    timeout_name.replace_range(..idx, "timeout");
                }
                let timeout_path = output_dir.join("timeout").join(timeout_name);
                if fs::copy(&self.path, timeout_path).is_err() {
                    error!("Error occurred while copying the file: {:?}", self.path);
                }
            } else if err.contains("Out of memory") {
                let mut oom_name = self
                    .path
                    .file_name()
                    .unwrap()
                    .to_os_string()
                    .into_string()
                    .unwrap();
                if let Some(idx) = oom_name.find('-') {
                    oom_name.replace_range(..idx, "oom");
                }
                let oom_path = output_dir.join("oom").join(oom_name);
                if fs::copy(&self.path, oom_path).is_err() {
                    error!("Error occurred while copying the file: {:?}", self.path);
                }
            } else if err.contains("Program terminated (no crash)") {
                warn!("{}: No crash on input {}", tool, self.path.display());
            } else {
                error!("{} for input: {}", err.trim(), self.path.display());
            }
        }

        Ok(())
    }
}

/// Perform analysis
///
/// # Arguments
///
/// `matches` - tool arguments
///
/// `crashes` - set of crashes, specified as a CrashInfo structure
///
/// `tool` - tool that generates reports
///
/// `gdb_argv` - arguments for casr-gdb
pub fn generate_reports(
    matches: &clap::ArgMatches,
    crashes: &HashMap<String, CrashInfo>,
    tool: &str,
    gdb_argv: &Vec<String>,
) -> Result<()> {
    // Get timeout
    let timeout = if let Some(timeout) = matches.get_one::<u64>("timeout") {
        *timeout
    } else {
        0
    };

    let (output_dir, _, _) = initialize_dirs(matches)?;

    let envs = if tool.eq("casr-python") {
        // Get Atheris asan_with_fuzzer library path.
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
        HashMap::from([(
            "LD_PRELOAD".to_string(),
            format!("{out}/asan_with_fuzzer.so"),
        )])
    } else {
        HashMap::new()
    };

    // Get number of threads
    let jobs = if let Some(jobs) = matches.get_one::<u32>("jobs") {
        *jobs as usize
    } else {
        std::cmp::max(1, num_cpus::get() / 2)
    };
    let num_of_threads = jobs.min(crashes.len()).max(1) + 1;
    let custom_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_of_threads)
        .build()
        .unwrap();

    // Generate CASR reports.
    info!("Generating CASR reports...");
    info!("Using {} threads", num_of_threads - 1);
    let counter = RwLock::new(0_usize);
    let total = crashes.len();
    custom_pool
        .join(
            || {
                crashes.par_iter().try_for_each(|(_, crash)| {
                    if let Err(e) = crash.run_casr(tool, output_dir.as_path(), timeout, &envs) {
                        // Disable util::log_progress
                        *counter.write().unwrap() = total;
                        bail!(e);
                    };
                    *counter.write().unwrap() += 1;
                    Ok::<(), anyhow::Error>(())
                })
            },
            || log_progress(&counter, total),
        )
        .0?;

    // Deduplicate reports.
    if output_dir.read_dir()?.count() < 2 {
        info!("There are less than 2 CASR reports, nothing to deduplicate.");
        return summarize_results(output_dir, crashes, gdb_argv, num_of_threads, timeout);
    }
    info!("Deduplicating CASR reports...");
    let casr_cluster_d = Command::new("casr-cluster")
        .arg("-d")
        .arg(output_dir.clone().into_os_string())
        .output()
        .with_context(|| "Couldn't launch casr-cluster".to_string())?;

    if casr_cluster_d.status.success() {
        info!(
            "{}",
            String::from_utf8_lossy(&casr_cluster_d.stdout)
                .lines()
                .collect::<Vec<&str>>()
                .join(". ")
        );
    } else {
        bail!("{}", String::from_utf8_lossy(&casr_cluster_d.stderr));
    }

    if !matches.get_flag("no-cluster") {
        if output_dir
            .read_dir()?
            .flatten()
            .map(|e| e.path())
            .filter(|e| e.extension().is_some() && e.extension().unwrap() == "casrep")
            .count()
            < 2
        {
            info!("There are less than 2 CASR reports, nothing to cluster.");
            return summarize_results(output_dir, crashes, gdb_argv, num_of_threads, timeout);
        }
        info!("Clustering CASR reports...");
        let casr_cluster_c = Command::new("casr-cluster")
            .arg("-c")
            .arg(output_dir.clone().into_os_string())
            .output()
            .with_context(|| "Couldn't launch casr-cluster".to_string())?;

        if casr_cluster_c.status.success() {
            info!(
                "{}",
                String::from_utf8_lossy(&casr_cluster_c.stdout).trim_end()
            );
        } else {
            error!("{}", String::from_utf8_lossy(&casr_cluster_c.stderr));
        }

        // Remove reports from deduplication phase. They are in clusters now.
        for casrep in fs::read_dir(output_dir)?.flatten().map(|e| e.path()) {
            if let Some(ext) = casrep.extension() {
                if ext == "casrep" {
                    let _ = fs::remove_file(casrep);
                }
            }
        }
    }

    summarize_results(output_dir, crashes, gdb_argv, num_of_threads, timeout)
}

/// Copy crashes next to reports and print summary.
/// Run casr-gdb on uninstrumented binary if specified in ARGS.
///
/// # Arguments
///
/// * `dir` - directory with casr reports
///
/// * `crashes` - crashes info
///
/// * `gdb_args` - run casr-gdb on uninstrumented binary if specified
///
/// * `jobs` - number of threads for casr-gdb reports generation
///
/// * `timeout` - target program timeout
fn summarize_results(
    dir: &Path,
    crashes: &HashMap<String, CrashInfo>,
    gdb_args: &Vec<String>,
    jobs: usize,
    timeout: u64,
) -> Result<()> {
    // Copy crashes next to reports
    copy_crashes(dir, crashes)?;

    if !gdb_args.is_empty() {
        // Run casr-gdb on uninstrumented binary.
        let crashes: Vec<_> = WalkDir::new(dir)
            .into_iter()
            .flatten()
            .map(|e| e.into_path())
            .filter(|e| e.is_file())
            .filter(|e| e.extension().is_none() || e.extension().unwrap() != "casrep")
            .filter(|e| !Path::new(format!("{}.gdb.casrep", e.display()).as_str()).exists())
            .collect();
        let num_of_threads = jobs.min(crashes.len() + 1);
        if num_of_threads > 1 {
            info!("casr-gdb: adding crash reports...");
            info!("Using {} threads", num_of_threads - 1);
            let counter = RwLock::new(0_usize);
            let total = crashes.len();
            let custom_pool = rayon::ThreadPoolBuilder::new()
                .num_threads(num_of_threads)
                .build()
                .unwrap();
            let at_index = gdb_args
                .iter()
                .skip(1)
                .position(|s| s.contains("@@"))
                .map(|x| x + 1);
            custom_pool
                .join(
                    || {
                        crashes.par_iter().try_for_each(|crash| {
                            if let Err(e) = (CrashInfo {
                                path: crash.to_path_buf(),
                                target_args: gdb_args.clone(),
                                at_index,
                                is_asan: false,
                            })
                            .run_casr(
                                "casr-gdb",
                                None,
                                timeout,
                                &HashMap::new(),
                            ) {
                                // Disable util::log_progress
                                *counter.write().unwrap() = total;
                                bail!(e);
                            };
                            *counter.write().unwrap() += 1;
                            Ok::<(), anyhow::Error>(())
                        })
                    },
                    || log_progress(&counter, total),
                )
                .0?;
        }
    }

    // Print summary
    let status = Command::new("casr-cli")
        .arg(dir)
        .stderr(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .status()
        .with_context(|| "Couldn't launch casr-cli".to_string())?;

    if !status.success() {
        error!("casr-cli exited with status {status}");
    }

    // Report ooms.
    let oom_dir = dir.join("oom");
    let oom_cnt = fs::read_dir(&oom_dir).unwrap().count();
    if oom_cnt != 0 {
        info!(
            "{} out of memory seeds are saved to {:?}",
            oom_cnt, &oom_dir
        );
    } else {
        fs::remove_dir_all(&oom_dir)?;
    }

    // Report timeouts.
    let timeout_dir = dir.join("timeout");
    let timeout_cnt = fs::read_dir(&timeout_dir).unwrap().count();
    if timeout_cnt != 0 {
        info!(
            "{} timeout seeds are saved to {:?}",
            timeout_cnt, &timeout_dir
        );
    } else {
        fs::remove_dir_all(&timeout_dir)?;
    }

    // Check bad reports.
    if let Ok(err_dir) = fs::read_dir(dir.join("clerr")) {
        warn!(
            "{} corrupted reports are saved to {:?}",
            err_dir
                .filter_map(|x| x.ok())
                .filter_map(|x| x.file_name().into_string().ok())
                .filter(|x| x.ends_with("casrep") && !x.ends_with("gdb.casrep"))
                .count(),
            &dir.join("clerr")
        );
    }

    Ok(())
}

/// Copy recursively crash inputs next to casr reports
///
/// # Arguments
///
/// `dir` - directory with casr reports
///
/// `crashes` - crashes info
fn copy_crashes(dir: &Path, crashes: &HashMap<String, CrashInfo>) -> Result<()> {
    for e in fs::read_dir(dir)?.flatten().map(|x| x.path()) {
        if e.is_dir() && e.file_name().unwrap().to_str().unwrap().starts_with("cl") {
            copy_crashes(&e, crashes)?;
        } else if e.is_file() && e.extension().is_some() && e.extension().unwrap() == "casrep" {
            let mut e = e.with_extension("");
            if e.extension().is_some() && e.extension().unwrap() == "gdb" {
                e = e.with_extension("");
            }
            let fname = e.file_name().unwrap().to_str().unwrap();
            if let Some(crash) = crashes.get(fname) {
                let _ = fs::copy(&crash.path, e);
            }
        }
    }

    Ok(())
}

/// Method checks whether binary file contains predefined symbols.
///
/// # Arguments
///
/// * `path` - path to binary to check.
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
