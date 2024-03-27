use casr::util;
use libcasr::report::CrashReport;
use libcasr::severity::Severity;
use libcasr::stacktrace::{CrashLine, CrashLineExt};
use libcasr::ubsan;
use libcasr::ubsan::UbsanWarning;

use anyhow::{bail, Context, Result};
use clap::{
    error::{ContextKind, ContextValue, ErrorKind},
    Arg, ArgAction,
};
use log::{debug, info, warn};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use regex::Regex;
use walkdir::WalkDir;

use std::collections::HashSet;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::RwLock;

/// Extract ubsan warnings for specified input file
///
/// # Arguments
///
/// * `input` - input file path
///
/// * `argv` - target program argument vector
///
/// * `timeout` - target program timeout
///
/// # Returns value
///
/// Vector of extracted ubsan warnings with crash lines
fn extract_warnings(
    input: &PathBuf,
    argv: &[&str],
    timeout: u64,
) -> Result<Vec<(UbsanWarning, CrashLine)>> {
    // Get command line argv
    let mut argv = argv.to_owned();
    let arg: String;
    let stdin = if let Some(index) = argv.iter().position(|&arg| arg.contains("@@")) {
        arg = argv[index].replace("@@", input.to_str().unwrap());
        argv[index] = &arg;
        false
    } else {
        true
    };
    // Run program.
    let mut cmd = Command::new(argv[0]);
    cmd.stdout(Stdio::null()).stderr(Stdio::piped());
    if stdin {
        let Ok(file) = fs::File::open(input) else {
            bail!("Can't open file {:?}", input);
        };
        cmd.stdin(file);
    }
    if argv.len() > 1 {
        cmd.args(&argv[1..]);
    }
    debug!("Run: {:?}", cmd);

    // Get output
    let output = util::get_output(&mut cmd, timeout, false)?;
    // Get stderr
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Extract ubsan warnings
    let extracted_warnings = ubsan::extract_ubsan_warnings(&stderr);
    // Update warning vector
    // Get position by input
    let mut warnings: Vec<(UbsanWarning, CrashLine)> = vec![];
    for warning in extracted_warnings {
        // Get crashline
        if let Ok(crashline) = warning.crash_line() {
            warnings.push((warning, crashline));
        } else {
            warn!(
                "Cannot get warning crash line for {}: {}",
                input.display(),
                warning.message
            );
        }
    }

    Ok(warnings)
}

/// Generate ubsan report for specified input file
///
/// # Arguments
///
/// * `input` - input file path
///
/// * `warning` - target warning
///
/// * `crashline` - warning crash line
///
/// * `argv` - target program argument vector
///
/// * `report` - report template containing identical values
///
/// # Returns value
///
/// Generated report
fn gen_report(
    input: &Path,
    warning: &UbsanWarning,
    crashline: &CrashLine,
    argv: &[&str],
    report: &CrashReport,
) -> CrashReport {
    // Get command line argv
    let mut argv = argv.to_owned();
    let arg: String;
    let stdin = if let Some(index) = argv.iter().position(|&arg| arg.contains("@@")) {
        arg = argv[index].replace("@@", input.to_str().unwrap());
        argv[index] = &arg;
        false
    } else {
        true
    };
    let args = argv.join(" ");
    debug!("Generating report for {:?}", args);
    // Create report
    let mut report = report.clone();
    report.proc_cmdline = args;
    report.ubsan_report = warning.ubsan_report();
    if stdin {
        report.stdin = input.to_str().unwrap().to_string();
    }
    // Get stacktrace
    if let Ok(stacktrace) = warning.extract_stacktrace() {
        report.stacktrace = stacktrace;
    }
    // Get execution class
    if let Ok(execution_class) = warning.severity() {
        report.execution_class = execution_class;
    }
    // Get crashline and source
    report.crashline = crashline.to_string();
    if let CrashLine::Source(debug) = crashline {
        if let Some(sources) = CrashReport::sources(debug) {
            report.source = sources;
        }
    }
    report
}

/// Save ubsan report and corresponding input
///
/// # Arguments
///
/// * `report` - saving report
///
/// * `output_dir` - report saving directory
///
/// * `input` - input file path
fn save_report(report: CrashReport, output_dir: &Path, input: &Path) -> Result<()> {
    // Convert report to string.
    let repstr = serde_json::to_string_pretty(&report).unwrap();

    let dir_name = input.parent().unwrap().file_name().unwrap();
    let input_name = input.file_name().unwrap();
    let crashline = report.crashline;
    let crashline = crashline.split('/').last().unwrap();
    let crashline = crashline.replace(':', "_");

    // Copy input
    let mut input_path = PathBuf::new();
    input_path.push(output_dir);
    input_path.push(format!(
        "{}_{}",
        dir_name.to_str().unwrap(),
        input_name.to_str().unwrap()
    ));
    fs::copy(input, input_path)?;

    let mut report_path = PathBuf::new();
    report_path.push(output_dir);
    report_path.push(format!(
        "{}_{}_{}.casrep",
        dir_name.to_str().unwrap(),
        input_name.to_str().unwrap(),
        crashline
    ));
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&report_path)
    {
        file.write_all(repstr.as_bytes()).with_context(|| {
            format!(
                "Couldn't write data to report file `{}`",
                &report_path.display()
            )
        })?;
    } else {
        bail!("Couldn't save report to file: {}", &report_path.display());
    }
    Ok(())
}

fn main() -> Result<()> {
    let matches = clap::Command::new("casr-ubsan")
        .version(clap::crate_version!())
        .about("Triage errors found by UndefinedBehaviorSanitizer and create CASR reports (.casrep)")
        .term_width(90)
        .arg(
            Arg::new("log-level")
                .long("log-level")
                .short('l')
                .action(ArgAction::Set)
                .default_value("info")
                .value_parser(["info", "debug"])
                .help("Logging level")
        )
        .arg(
            Arg::new("jobs")
                .long("jobs")
                .short('j')
                .action(ArgAction::Set)
                .help("Number of parallel jobs for generating CASR reports [default: half of cpu cores]")
                .value_parser(clap::value_parser!(u32).range(1..))
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .action(ArgAction::Set)
                .default_value("0")
                .value_name("SECONDS")
                .help("Timeout (in seconds) for target execution, 0 value means that timeout is disabled")
                .value_parser(clap::value_parser!(u64))
        )
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .action(ArgAction::Set)
                .required(true)
                .num_args(1..)
                .value_name("INPUT_DIRS")
                .help("Target input directory list")
                .value_parser(move |arg: &str| {
                    let i_dir = Path::new(arg);
                    if !i_dir.exists() {
                        let mut err = clap::Error::new(ErrorKind::ValueValidation);
                        err.insert(ContextKind::InvalidValue, ContextValue::String("Input directory doesn't exist.".to_owned()));
                        return Err(err);
                    }
                    if !i_dir.is_dir() {
                        let mut err = clap::Error::new(ErrorKind::ValueValidation);
                        err.insert(ContextKind::InvalidValue, ContextValue::String("Input path should be a directory.".to_owned()));
                        return Err(err);
                    }
                    Ok(i_dir.to_path_buf())
                })
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .action(ArgAction::Set)
                .required(true)
                .value_name("OUTPUT_DIR")
                .value_parser(clap::value_parser!(PathBuf))
                .help("Output directory with triaged reports")
        )
        .arg(
            Arg::new("force-remove")
                .short('f')
                .long("force-remove")
                .action(ArgAction::SetTrue)
                .help("Remove output project directory if it exists")
        )
        .arg(
            Arg::new("ARGS")
                .action(ArgAction::Set)
                .required(false)
                .num_args(1..)
                .last(true)
                .required(true)
                .help("Add \"-- <path> <arguments>\" to run"),
        )
        .get_matches();

    // Init log.
    util::initialize_logging(&matches);

    // Get input dir list
    let input_dirs: Vec<_> = matches.get_many::<PathBuf>("input").unwrap().collect();
    // Get output dir
    let output_dir = matches.get_one::<PathBuf>("output").unwrap();
    if !output_dir.exists() {
        fs::create_dir_all(output_dir).with_context(|| {
            format!("Couldn't create output directory {}", output_dir.display())
        })?;
    } else if !output_dir.is_dir() {
        bail!("Output directory must be a directory");
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
    // Get program args.
    let argv: Vec<&str> = if let Some(argvs) = matches.get_many::<String>("ARGS") {
        argvs.map(|s| s.as_str()).collect()
    } else {
        bail!("Wrong arguments for starting program");
    };

    // Get timeout
    let timeout = *matches.get_one::<u64>("timeout").unwrap();

    // Get input path list
    let mut inputs: Vec<PathBuf> = vec![];
    // Do without paralleling to preserve the specified order
    for input_dir in input_dirs {
        for path in WalkDir::new(input_dir)
            .sort_by_file_name()
            .into_iter()
            .filter_map(|file| file.ok())
            .filter(|file| file.metadata().unwrap().is_file())
            .map(|file| file.path().to_path_buf())
        {
            inputs.push(path);
        }
    }

    // Get number of threads
    let jobs = if let Some(jobs) = matches.get_one::<u32>("jobs") {
        *jobs as usize
    } else {
        std::cmp::max(1, num_cpus::get() / 2)
    };
    let num_of_threads = jobs.min(inputs.len()).max(1) + 1;
    let custom_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_of_threads)
        .build()
        .unwrap();

    // Set ubsan env options
    if let Ok(mut ubsan_options) = env::var("UBSAN_OPTIONS") {
        if ubsan_options.starts_with(',') {
            ubsan_options.remove(0);
        }
        if ubsan_options.contains("print_stacktrace=0") {
            ubsan_options = ubsan_options.replace("print_stacktrace=0", "print_stacktrace=1");
        } else {
            ubsan_options.push_str(",print_stacktrace=1");
        }
        if ubsan_options.contains("report_error_type=0") {
            ubsan_options = ubsan_options.replace("report_error_type=0", "report_error_type=1");
        } else {
            ubsan_options.push_str(",report_error_type=1");
        }
        if ubsan_options.contains("symbolize=0") {
            ubsan_options = ubsan_options.replace("symbolize=0", "symbolize=1");
        } else {
            ubsan_options.push_str(",symbolize=1");
        }
        env::set_var("UBSAN_OPTIONS", ubsan_options);
    } else {
        env::set_var(
            "UBSAN_OPTIONS",
            "print_stacktrace=1,report_error_type=1,symbolize=1",
        );
    }

    // Extract ubsan warnings
    info!("Extracting UBSAN warnings...");
    info!("Using {} threads", num_of_threads - 1);
    let counter = RwLock::new(0_usize);
    let total = inputs.len();
    type Warning<'a> = (&'a PathBuf, Vec<(UbsanWarning, CrashLine)>);
    let (warnings, _): (Vec<Warning>, _) = custom_pool.join(
        || {
            inputs
                .par_iter()
                .filter_map(|input| {
                    let Ok(input_warnings) = extract_warnings(input, &argv, timeout) else {
                        warn!("Failed to run program with input file {:?}", input);
                        *counter.write().unwrap() += 1;
                        return None;
                    };
                    *counter.write().unwrap() += 1;
                    Some((input, input_warnings))
                })
                .collect()
        },
        || util::log_progress(&counter, total),
    );

    info!(
        "Number of UBSAN warnings: {}",
        warnings
            .iter()
            .map(|(_, input_warnings)| input_warnings.len())
            .sum::<usize>()
    );

    // Create report with equal parts for all reports
    let mut pre_report = CrashReport::new();
    pre_report.executable_path = argv[0].to_string();
    let _ = pre_report.add_os_info();
    let _ = pre_report.add_proc_environ();

    info!("Deduplicating CASR reports...");
    // Init dedup crashline list
    let mut crashlines: HashSet<String> = HashSet::new();
    let mut to_gen: Vec<(PathBuf, UbsanWarning, CrashLine)> = vec![];
    // Dedup warnings by crashline
    // Do without paralleling to preserve the specified order
    let re = Regex::new(r"(.+:\d+):\d").unwrap();
    for (input, input_warnings) in warnings {
        for (warning, crashline) in input_warnings {
            // Drop column number
            let mut line = crashline.to_string();
            if let Some(cap) = re.captures(&line) {
                line = cap.get(1).unwrap().as_str().to_string();
            }
            if crashlines.insert(line) {
                to_gen.push((input.clone(), warning, crashline));
            }
        }
    }

    info!(
        "Number of UBSAN warnings after deduplication: {}",
        crashlines.len()
    );

    // Rebuild thread pool (different number of threads)
    let num_of_threads = jobs.min(to_gen.len()).max(1);
    let custom_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_of_threads)
        .build()
        .unwrap();

    // Generate CASR reports
    info!("Generating CASR reports...");
    custom_pool.install(|| {
        to_gen
            .par_iter()
            .try_for_each(|(input, warning, crashline)| {
                let report = gen_report(input, warning, crashline, &argv, &pre_report);
                // Save report
                save_report(report, output_dir, input)
            })
    })?;

    Ok(())
}
