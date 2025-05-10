use casr::util;
use libcasr::{
    asan::AsanCrash,
    init_ignored_frames,
    lua::LuaException,
    report::{CrashReport, ReportExtractor},
    stacktrace::CrashLine,
    stacktrace::Filter,
    stacktrace::Stacktrace,
};

use anyhow::{Result, bail};
use clap::{Arg, ArgAction, ArgGroup, ArgMatches};

use std::env;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug)]
enum Mode {
    Lua,
    San,
}

impl Mode {
    fn new(mode: &str) -> Result<Mode> {
        match mode {
            "lua" => Ok(Mode::Lua),
            "san" => Ok(Mode::San),
            _ => {
                bail!("Unexpected mode: {}", mode);
            }
        }
    }
}

fn get_mode(matches: &ArgMatches, argv: &[&str]) -> Result<Mode> {
    let subcommand = matches.subcommand_name();
    if subcommand.is_some() && subcommand.unwrap() != "auto" {
        Ok(Mode::new(subcommand.unwrap())?)
    } else if argv[0].ends_with(".lua") {
        Ok(Mode::Lua)
    } else {
        let sym_list = util::symbols_list(Path::new(argv[0]))?;
        if sym_list.contains("__asan") || sym_list.contains("runtime.go") {
            Ok(Mode::San)
        } else {
            // TODO: gdb
            bail!("PLACEME");
        }
    }
}

fn prepare_run_san() {
    // Set rss limit.
    if let Ok(asan_options_str) = env::var("ASAN_OPTIONS") {
        let mut asan_options = asan_options_str.clone();
        if !asan_options_str.contains("hard_rss_limit_mb") {
            asan_options = [asan_options.as_str(), "hard_rss_limit_mb=2048"].join(",");
        }
        if asan_options.starts_with(',') {
            asan_options.remove(0);
        }
        asan_options = asan_options.replace("symbolize=0", "symbolize=1");
        unsafe {
            std::env::set_var("ASAN_OPTIONS", asan_options);
        }
    } else {
        unsafe {
            std::env::set_var("ASAN_OPTIONS", "hard_rss_limit_mb=2048");
        }
    }
}

fn prepare_run(mode: &Mode) {
    match mode {
        Mode::San => {
            prepare_run_san();
        }
        _ => {}
    }
}

fn update_cmd_san(cmd: &mut Command) {
    #[cfg(target_os = "macos")]
    {
        cmd.env("DYLD_NO_PIE", "1");
    }
    #[cfg(target_os = "linux")]
    {
        use linux_personality::{Personality, personality};

        unsafe {
            cmd.pre_exec(|| {
                if personality(Personality::ADDR_NO_RANDOMIZE).is_err() {
                    panic!("Cannot set personality");
                }
                Ok(())
            })
        };
    }
}

fn update_cmd(cmd: &mut Command, mode: &Mode) {
    match mode {
        Mode::San => {
            update_cmd_san(cmd);
        }
        _ => {}
    }
}

fn update_report_stub_lua(report: &mut CrashReport, argv: &[&str]) {
    if argv.len() > 1 {
        if let Some(fname) = Path::new(argv[0]).file_name() {
            let fname = fname.to_string_lossy();
            if fname.starts_with("lua") && !fname.ends_with(".lua") && argv[1].ends_with(".lua") {
                report.executable_path = argv[1].to_string();
            }
        }
    }
}

fn update_report_stub_san(report: &mut CrashReport, stdin_file: &Option<PathBuf>) {
    if let Some(mut file_path) = stdin_file.clone() {
        file_path = file_path.canonicalize().unwrap_or(file_path);
        report.stdin = file_path.display().to_string();
    }
}

fn get_report_stub(argv: &Vec<&str>, stdin_file: &Option<PathBuf>, mode: &Mode) -> CrashReport {
    let mut report = CrashReport::new();
    report.executable_path = argv[0].to_string();
    report.proc_cmdline = argv.join(" ");
    let _ = report.add_os_info();
    let _ = report.add_proc_environ();
    match mode {
        Mode::Lua => {
            update_report_stub_lua(&mut report, argv);
        }
        Mode::San => {
            update_report_stub_san(&mut report, stdin_file);
        }
    }
    report
}

fn get_extracter(_stdout: &str, stderr: &str, mode: &Mode) -> Result<Box<dyn ReportExtractor>> {
    match mode {
        Mode::Lua => {
            let Some(exception) = LuaException::new(stderr) else {
                bail!("Lua exception is not found!");
            };
            Ok(Box::new(exception))
        }
        Mode::San => {
            // TODO: adjust mode value
            if let Some(crash) = AsanCrash::new(stderr)? {
                Ok(Box::new(crash))
            } else {
                bail!("Make me");
            }
        }
    }
}

// NOTE: if there were no different report fields this function would not be needed
fn fill_report(report: &mut CrashReport, raw_report: Vec<String>, mode: &Mode) -> Result<()> {
    match mode {
        Mode::Lua => {
            report.lua_report = raw_report;
        }
        Mode::San => {
            report.asan_report = raw_report;
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let matches = clap::Command::new("casr")
        .version(clap::crate_version!())
        .about("Create CASR reports (.casrep) from target output")
        .term_width(90)
        .arg(
            Arg::new("output")
                .long("output")
                .short('o')
                .global(true)
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .value_name("REPORT")
                .help(
                    "Path to save report. Path can be a directory, then report name is generated",
                ),
        )
        .arg(
            Arg::new("stdout")
                .long("stdout")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Print CASR report to stdout"),
        )
        .group(
            ArgGroup::new("out")
                .args(["stdout", "output"])
                //.required(true),
        )
        .arg(
            Arg::new("stdin")
                .long("stdin")
                .global(true)
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .value_name("FILE")
                .help("Stdin file for program"),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .short('t')
                .global(true)
                .action(ArgAction::Set)
                .default_value("0")
                .value_name("SECONDS")
                .help("Timeout (in seconds) for target execution, 0 value means that timeout is disabled")
                .value_parser(clap::value_parser!(u64))
        )
        .arg(
            Arg::new("ignore")
                .long("ignore")
                .global(true)
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .value_name("FILE")
                .help("File with regular expressions for functions and file paths that should be ignored"),
        )
        .arg(
            Arg::new("strip-path")
                .long("strip-path")
                .env("CASR_STRIP_PATH")
                .global(true)
                .action(ArgAction::Set)
                .value_name("PREFIX")
                .help("Path prefix to strip from stacktrace"),
        )
        .arg(
            Arg::new("ld-preload")
                .long("ld-preload")
                .env("CASR_PRELOAD")
                .global(true)
                .action(ArgAction::Set)
                .num_args(1..)
                .value_name("LIBS")
                .value_parser(clap::value_parser!(String))
                .help("Set LD_PRELOAD for the target program without disrupting the CASR process itself (both ` ` and `:` are valid delimiter)")
        )
        .arg(
            Arg::new("ARGS")
                .action(ArgAction::Set)
                .num_args(1..)
                .last(true)
                //.required(true)
                .global(true)
                .help("Add \"-- <path> <arguments>\" to run"),
        )
        .subcommands([
            clap::Command::new("auto")
                .about("Auto define proper way to threat target output (default behavior)"),
            clap::Command::new("san")
                .about("Threat target output as AddressSanitizer or MemorySanitizer reports"),
            clap::Command::new("lua")
                .about("Threat target output as Lua reports")
        ])
        .get_matches();

    // TODO: manually validate required args: stdout/output, ARGS
    init_ignored_frames!("go", "lua", "rust", "san");

    if let Some(path) = matches.get_one::<PathBuf>("ignore") {
        util::add_custom_ignored_frames(path)?;
    }
    // Get program args.
    let argv: Vec<&str> = if let Some(argvs) = matches.get_many::<String>("ARGS") {
        argvs.map(|s| s.as_str()).collect()
    } else {
        bail!("Wrong arguments for starting program");
    };

    // Get stdin for target program.
    let stdin_file = util::stdin_from_matches(&matches)?;

    // Get timeout
    let timeout = *matches.get_one::<u64>("timeout").unwrap();

    // Get mode
    let mode = get_mode(&matches, &argv)?;

    // Prepare run
    prepare_run(&mode);

    // Run program.
    let mut cmd = Command::new(argv[0]);
    // Set ld preload
    if let Some(ld_preload) = util::get_ld_preload(&matches) {
        cmd.env("LD_PRELOAD", ld_preload);
    }
    if let Some(ref file) = stdin_file {
        cmd.stdin(std::fs::File::open(file)?);
    }
    if argv.len() > 1 {
        cmd.args(&argv[1..]);
    }
    // Update mode-dependent characteristics
    update_cmd(&mut cmd, &mode);
    // Get output
    let result = util::get_output(&mut cmd, timeout, true)?;
    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);

    // Create report
    let mut report = get_report_stub(&argv, &stdin_file, &mode);

    // Get report extractor
    let mut extractor = get_extracter(&stdout, &stderr, &mode)?;

    // Extract report
    fill_report(&mut report, extractor.report(), &mode)?;
    report.stacktrace = extractor.extract_stacktrace()?;
    report.execution_class = extractor.execution_class()?;
    if let Ok(crashline) = extractor.crash_line() {
        report.crashline = crashline.to_string();
        if let CrashLine::Source(debug) = crashline {
            if let Some(sources) = CrashReport::sources(&debug) {
                report.source = sources;
            }
        }
    }
    let stacktrace = extractor.parse_stacktrace()?;
    if let Some(path) = matches.get_one::<String>("strip-path") {
        util::strip_paths(&mut report, &stacktrace, path);
    }

    //Output report
    util::output_report(&report, &matches, &argv)
}
