# Usage

CASR is a set of tools that allows you to collect crash reports in different
ways. Use `casr-core` binary to deal with coredumps. Use `casr-san` to analyze
ASAN reports or `casr-ubsan` to analyze UBSAN reports. Try `casr-gdb` to get
reports from gdb. Use `casr-python` to analyze python reports and get report
from [Atheris](https://github.com/google/atheris). Use `casr-java` to analyze
java reports and get report from
[Jazzer](https://github.com/CodeIntelligenceTesting/jazzer). Use `casr-js` to
analyze JavaScript reports and get report from
[Jazzer.js](https://github.com/CodeIntelligenceTesting/jazzer.js) or
[jsfuzz](https://github.com/fuzzitdev/jsfuzz). Use `casr-csharp` to analyze C#
reports and get report from [Sharpfuzz](https://github.com/Metalnem/sharpfuzz).
Use `casr-lua` to analyze Lua reports. `casr-afl` can triage crashes found by
[AFL++](https://github.com/AFLplusplus/AFLplusplus) and AFL-based fuzzer
[Sharpfuzz](https://github.com/Metalnem/sharpfuzz). `casr-libfuzzer` can triage
crashes found by [libFuzzer](https://www.llvm.org/docs/LibFuzzer.html)
(libFuzzer, go-fuzz, Atheris, Jazzer, Jazzer.js, jsfuzz, luzer) or by
[LibAFL](https://github.com/AFLplusplus/LibAFL) based
[fuzzers](https://github.com/AFLplusplus/LibAFL/tree/main/fuzzers). `casr-dojo`
allows to upload new and unique CASR reports to
[DefectDojo](https://github.com/DefectDojo/django-DefectDojo). `casr-cli` is
meant to provide TUI for viewing reports and converting them into SARIF report.
Reports triage (deduplication, clustering) is done by `casr-cluster`.

## casr-gdb

Create CASR reports (.casrep) from gdb execution

    Usage: casr-gdb [OPTIONS] <--stdout|--output <REPORT>> -- <ARGS>...

    Arguments:
      <ARGS>...  Add "-- ./binary <arguments>" to run executable

    Options:
      -o, --output <REPORT>      Path to save report. Path can be a directory, then report
                                 name is generated
          --stdout               Print CASR report to stdout
          --stdin <FILE>         Stdin file for program
      -t, --timeout <SECONDS>    Timeout (in seconds) for target execution, 0 value means that
                                 timeout is disabled [default: 0]
          --ignore <FILE>        File with regular expressions for functions and file paths
                                 that should be ignored
          --strip-path <PREFIX>  Path prefix to strip from stacktrace and crash line [env:
                                 CASR_STRIP_PATH=]
      -h, --help                 Print help
      -V, --version              Print version

Example:

    $ casr-gdb -o destAv.gdb.casrep -- casr/tests/casr_tests/bin/test_destAv $(printf 'A%.s' {1..200})

## casr-san

Create CASR reports (.casrep) from AddressSanitizer reports

    Usage: casr-san [OPTIONS] <--stdout|--output <REPORT>> -- <ARGS>...

    Arguments:
      <ARGS>...  Add "-- ./binary <arguments>" to run executable

    Options:
      -o, --output <REPORT>      Path to save report. Path can be a directory, then report
                                 name is generated
          --stdout               Print CASR report to stdout
          --stdin <FILE>         Stdin file for program
      -t, --timeout <SECONDS>    Timeout (in seconds) for target execution, 0 value means that
                                 timeout is disabled [default: 0]
          --ignore <FILE>        File with regular expressions for functions and file paths
                                 that should be ignored
          --strip-path <PREFIX>  Path prefix to strip from stacktrace and crash line [env:
                                 CASR_STRIP_PATH=]
      -h, --help                 Print help
      -V, --version              Print version

Compile binary with ASAN:

    $ clang++ -fsanitize=address -O0 -g casr/tests/casr_tests/test_asan_df.cpp -o test_asan_df

Run casr-san:

    $ casr-san -o asan.casrep -- ./test_asan_df

If you are using casr-san in docker container modify your seccomp profile to allow
personality syscall (details can be found [here](https://docs.docker.com/engine/security/seccomp/)).

If you are using casr-san to get CASR report for Rust fuzz target, you can choose between
ASAN stacktrace or Rust backtrace to analyze. If environment variable
`RUST_BACKTRACE=(1|full)` is specified, then Rust backtrace is considered.

## casr-ubsan

Triage errors found by UndefinedBehaviorSanitizer and create CASR reports (.casrep)

    Usage: casr-ubsan [OPTIONS] --input <INPUT_DIRS>... --output <OUTPUT_DIR> -- <ARGS>...

    Arguments:
      <ARGS>...  Add "-- <path> <arguments>" to run

    Options:
      -l, --log-level <log-level>  Logging level [default: info] [possible values: info,
                                   debug]
      -j, --jobs <jobs>            Number of parallel jobs for generating CASR reports
                                   [default: half of cpu cores]
      -t, --timeout <SECONDS>      Timeout (in seconds) for target execution, 0 value means
                                   that timeout is disabled [default: 0]
      -i, --input <INPUT_DIRS>...  Target input directory list
      -o, --output <OUTPUT_DIR>    Output directory with triaged reports
      -f, --force-remove           Remove output project directory if it exists
      -h, --help                   Print help
      -V, --version                Print version

Compile binary with UBSAN:

    $ clang++ -fsanitize=undefined -O0 -g casr/tests/casr_tests/ubsan/test_ubsan.cpp -o test_ubsan

Run casr-ubsan:

    $ casr-ubsan -i casr/tests/casr_tests/ubsan/input1 -o output -- ./test_ubsan @@

Get summary:

    $ casr-cli output

Ubsan error deduplication is based on crashline comparison. The idea is to run
deduplication to remove equal ubsan errors, then run report generation.

## casr-python

Create CASR reports (.casrep) from python reports

    Usage: casr-python [OPTIONS] <--stdout|--output <REPORT>> -- <ARGS>...

    Arguments:
      <ARGS>...  Add "-- <path> <arguments>" to run

    Options:
      -o, --output <REPORT>      Path to save report. Path can be a directory, then report
                                 name is generated
          --stdout               Print CASR report to stdout
          --stdin <FILE>         Stdin file for program
      -t, --timeout <SECONDS>    Timeout (in seconds) for target execution, 0 value means that
                                 timeout is disabled [default: 0]
          --ignore <FILE>        File with regular expressions for functions and file paths
                                 that should be ignored
          --strip-path <PREFIX>  Path prefix to strip from stacktrace [env: CASR_STRIP_PATH=]
      -h, --help                 Print help
      -V, --version              Print version

Example:

    $ casr-python -o python.casrep -- casr/tests/casr_tests/python/test_casr_python.py

## casr-java

Create CASR reports (.casrep) from java reports

    Usage: casr-java [OPTIONS] <--stdout|--output <REPORT>> -- <ARGS>...

    Arguments:
      <ARGS>...  Add "-- <path> <arguments>" to run

    Options:
      -o, --output <REPORT>       Path to save report. Path can be a directory, then report
                                  name is generated
          --stdout                Print CASR report to stdout
          --stdin <FILE>          Stdin file for program
          --source-dirs <DIR>...  Paths to directories with Java source files (list separated
                                  by ':' for env) [env: CASR_SOURCE_DIRS=]
      -t, --timeout <SECONDS>     Timeout (in seconds) for target execution, 0 value means
                                  that timeout is disabled [default: 0]
          --ignore <FILE>         File with regular expressions for functions and file paths
                                  that should be ignored
          --strip-path <PREFIX>   Path prefix to strip from stacktrace and crash line [env:
                                  CASR_STRIP_PATH=]
      -h, --help                  Print help
      -V, --version               Print version

Run casr-java:

    $ casr-java -o java.casrep -- java casr/tests/casr_tests/java/Test1.java

## casr-js

Create CASR reports (.casrep) from JavaScript crash reports

    Usage: casr-js [OPTIONS] <--stdout|--output <REPORT>> -- <ARGS>...

    Arguments:
      <ARGS>...  Add "-- <path> <arguments>" to run

    Options:
      -o, --output <REPORT>      Path to save report. Path can be a directory, then report
                                 name is generated
          --stdout               Print CASR report to stdout
          --stdin <FILE>         Stdin file for program
      -t, --timeout <SECONDS>    Timeout (in seconds) for target execution, 0 value means that
                                 timeout is disabled [default: 0]
          --ignore <FILE>        File with regular expressions for functions and file paths
                                 that should be ignored
          --strip-path <PREFIX>  Path prefix to strip from stacktrace and crash line [env:
                                 CASR_STRIP_PATH=]
      -h, --help                 Print help
      -V, --version              Print version

Run casr-js:

    $ casr-js -o js.casrep -- node casr/tests/casr_tests/js/test_casr_js.js

## casr-csharp

Create CASR reports (.casrep) from C# reports

    Usage: casr-csharp [OPTIONS] <--stdout|--output <REPORT>> -- <ARGS>...

    Arguments:
      <ARGS>...  Add "-- <path> <arguments>" to run

    Options:
      -o, --output <REPORT>      Path to save report. Path can be a directory, then report
                                 name is generated
          --stdout               Print CASR report to stdout
          --stdin <FILE>         Stdin file for program
      -t, --timeout <SECONDS>    Timeout (in seconds) for target execution, 0 value means that
                                 timeout is disabled [default: 0]
          --ignore <FILE>        File with regular expressions for functions and file paths
                                 that should be ignored
          --strip-path <PREFIX>  Path prefix to strip from stacktrace and crash line [env:
                                 CASR_STRIP_PATH=]
      -h, --help                 Print help
      -V, --version              Print version

Run casr-csharp:

    $ casr-csharp -o csharp.casrep -- dotnet run --project casr/tests/casr_tests/csharp/test_casr_csharp/test_casr_csharp.csproj

## casr-lua

Create CASR reports (.casrep) from Lua reports

    Usage: casr-lua [OPTIONS] <--stdout|--output <REPORT>> -- <ARGS>...

    Arguments:
      <ARGS>...  Add "-- <path> <arguments>" to run

    Options:
      -o, --output <REPORT>      Path to save report. Path can be a directory, then report
                                 name is generated
          --stdout               Print CASR report to stdout
          --stdin <FILE>         Stdin file for program
      -t, --timeout <SECONDS>    Timeout (in seconds) for target execution, 0 value means that
                                 timeout is disabled [default: 0]
          --ignore <FILE>        File with regular expressions for functions and file paths
                                 that should be ignored
          --strip-path <PREFIX>  Path prefix to strip from stacktrace [env: CASR_STRIP_PATH=]
      -h, --help                 Print help
      -V, --version              Print version

Run casr-lua:

    $ casr-lua -o lua.casrep -- casr/tests/casr_tests/lua/test_casr_lua.lua

## casr-core

Analyze coredump for security goals and provide detailed report with severity estimation

    Usage: casr-core [OPTIONS]

    Options:
      -m, --mode <MODE>        Offline mode analyzes collected coredumps, online mode
                               intercepts coredumps via core_pattern [default: offline]
                               [possible values: online, offline]
      -f, --file <FILE>        Path to input core file
      -o, --output <FILE>      Path to save report in JSON format
          --stdout             Print CASR report to stdout
      -e, --executable <FILE>  Path to executable
      -h, --help               Print help
      -V, --version            Print version

`casr-core` have two modes: offline and online. Offline mode is used by default. You
may create report when you already have a coredump file.

Example:

    $ casr-core -f casr/tests/casr_tests/bin/core.test_destAv -e casr/tests/casr_tests/bin/test_destAv -o destAv.casrep

In online mode `casr-core` could intercept crashes via core\_pattern. You
should do the following steps.

Create directory `/var/crash` and set permissions for it:

    $ sudo mkdir -m 777 /var/crash

Update core\_pattern:

    $ echo "|<path_to_casr_core_binary> -m online -c %c -p %p  -P %P -u %u -g %g -e %E" | sudo tee /proc/sys/kernel/core_pattern

Set core ulimit to unlimited or another non-zero value:

    $ ulimit -c unlimited

To test just crash some programs:

    $ cd casr/tests/casr_tests/bin && ./run.sh

Reports and coredumps will be stored in `/var/crash` directory.

## casr-cluster

Tool for clustering CASR reports

    Usage: casr-cluster [OPTIONS]

    Options:
      -s, --similarity <CASREP1> <CASREP2>
              Similarity between two CASR reports
      -c, --cluster <INPUT_DIR> <OUTPUT_DIR>
              Cluster CASR reports. If two directories are set, clusters will be placed in the
              second directory. If one directory is provided, clusters will be placed there,
              but reports in this directory will not be deleted.
          --unique-crashline
              Leave reports with unique crash lines in each cluster [env:
              CASR_CLUSTER_UNIQUE_CRASHLINE=]
      -d, --deduplicate <INPUT_DIR> <OUTPUT_DIR>
              Deduplicate CASR reports. If two directories are set, deduplicated reports are
              copied to the second directory. If one directory is provided, duplicated reports
              are deleted.
      -m, --merge <INPUT_DIR> <OUTPUT_DIR>
              Merge INPUT_DIR into OUTPUT_DIR. Only new CASR reports from INPUT_DIR will be
              added to OUTPUT_DIR.
      -u, --update <NEW_DIR> <OLD_DIR>
              Update clusters in OLD_DIR using CASR reports from NEW_DIR
      -e, --estimate <DIR>
              Calculate silhouette score for clustering results
          --diff <NEW_DIR> <PREV_DIR> <DIFF_DIR>
              Compute report sets difference NEW_DIR \ PREV_DIR. Copy new CASR reports from
              NEW_DIR into DIFF_DIR.
          --ignore <FILE>
              File with regular expressions for functions and file paths that should be
              ignored
      -j, --jobs <N>
              Number of parallel jobs to collect CASR reports
      -h, --help
              Print help
      -V, --version
              Print version

Report deduplication and clustering is based on stack trace comparison from
[gdb-command](https://github.com/anfedotoff/gdb-command). The idea is to run
deduplication first to remove equal reports, then run clustering on remaining
reports.

Example:

    $ casr-cluster -d casr/tests/casr_tests/casrep/test_clustering_gdb out-dedup
    $ casr-cluster -c out-dedup out-cluster

After clustering result directory will have the following structure:

    out-cluster
    ├── cl1
    │   ├── crash-2509d035b2e80f9a581d3aa8d06cfc69e0c039b5.casrep
    │   ├── crash-a791b3987d2f0df9e23ea6391f4fdf7668efec43.casrep
    │   └── crash-c30769502be4b694429b2f6fefd711077f8d74a9.casrep
    ├── cl10
    │   ├── crash-846a04c66ae6f00ebba8419366560f026edef55d.casrep
    │   └── crash-a3b2b686d60ee4fe01894e7fb4d51993567d344b.casrep
    ├── cl11
    │   ├── crash-3dc833a82a0cf5a8e59c375de8b3c0593697f430.casrep
    │   └── crash-d99121840f0da6ead4a850672450fe72d1fdfd20.casrep
    ├── cl12
    │   ├── crash-8c9af71da1ab74220b6a1ed2351c7a2998499a6d.casrep
    │   └── crash-e66fa015ed8b678c7670a1fb6056b7bc01da4da8.casrep
    ├── cl13
    │   └── crash-a04315b661e020c8a4e0cc566c75a765268270cb.casrep
    ├── cl2
    │   └── crash-a9ae83bf106b3b0922e49c5e39d5bf243dba9cf1.casrep
    ├── cl3
    │   └── crash-c886939eb1d08b7441f5c7db5214880e9edb6293.casrep
    ├── cl4
    │   └── crash-f76c353b794463ac1bdcc29e8f5d745984c6ecee.casrep
    ├── cl5
    │   └── crash-c1d84a4e0b4fe5a76c409d3036124131eeed0916.casrep
    ├── cl6
    │   └── crash-8272d5348f16766c950732bbaad7b32cd4b34d2b.casrep
    ├── cl7
    │   └── crash-ed08a8b8940f9209614092f3a8eef49e271797eb.casrep
    ├── cl8
    │   ├── crash-18ff5f889c2077dbb2caa8daab9a0b8160c99732.casrep
    │   └── crash-31464ed3fafb976c6e11cba8ddda7a5277b97755.casrep
    └── cl9
        └── crash-76f90b8ba0ee1e10f04692607a2aae17a1ced499.casrep

Similar CASR reports are inside one cluster.

Report accumulation is based on stack trace comparison, recognition similar
stack traces and clustering with merging different ones.

Example:

    $ casr-cluster -c casr/tests/casr_tests/casrep/test_clustering_small out
    $ rm -f out/cl9/40.casrep out/cl7/20.casrep && rm -rf out/cl8 && mv out/cl9 out/cl8
    $ casr-cluster -u casr/tests/casr_tests/casrep/test_clustering_small out

For the **--ignore <FILE>** option, file format should be as follows:

    FUNCTIONS
    /*ignored regexs for function names*/
    FILES
    /*ignored regexs for file paths*/

Headers may be in different order, one of them may be missing.
Frames that match these regular expressions will be not considered during analysis.

For `CASR_CLUSTER_UNIQUE_CRASHLINE` a `false` literal is `n`, `no`, `f`,
`false`, `off` or `0`. An absent environment variable will also be considered as
`false`. Anything else will considered as true.

## casr-cli

App provides text-based user interface to view CASR reports, prints joint statistics for
all reports, and converts CASR reports to SARIF format.

    Usage: casr-cli [OPTIONS] <REPORT|DIR>

    Arguments:
      <REPORT|DIR>  CASR report file to view or directory with reports

    Options:
      -v, --view <MODE>          View mode [default: tree] [possible values: tree, slider,
                                 stdout]
      -u, --unique               Print only unique crash lines in joint statistics
          --sarif <OUTPUT>       Generate SARIF report from CASR reports
          --source-root <PATH>   Source root path in CASR reports for SARIF report generation
          --tool <NAME>          Tool name that detected crashes/errors for SARIF report
                                 [default: CASR]
          --strip-path <PREFIX>  Path prefix to strip from crash path in joint report
                                 statistics [env: CASR_STRIP_PATH=]
      -h, --help                 Print help
      -V, --version              Print version

There are three view modes: tree, slider (list), and stdout. In stdout mode
`casr-cli` prints text-based CASR report to stdout.

`casr-cli` can convert a directory with casr reports or single report into SARIF
report. You could load resulting SARIF report into IDE and continue crash
analysis.

Example:

    $ casr-cli casr/tests/casr_tests/casrep/test_clustering_san/load_fuzzer_crash-120697a7f5b87c03020f321c8526adf0f4bcc2dc.casrep

Joint statistics about crash clusters:

    $ casr-cli casr_reports

Convert reports to SARIF report:

    $ casr-cli --sarif out.sarif --tool libfuzzer --source-root /xlnt casr/tests/casr_tests/casrep/test_clustering_san

### Screenshots

![casrep](/docs/images/casr_report.png)

![sarif](/docs/images/casr_sarif.png)

## casr-afl

Triage crashes found by AFL++/Sharpfuzz

    Usage: casr-afl [OPTIONS] --input <INPUT_DIR> --output <OUTPUT_DIR> [-- <ARGS>...]

    Arguments:
      [ARGS]...  Add "-- ./gdb_fuzz_target <arguments>" to generate additional crash reports
                 with casr-gdb (for compiled binaries, e.g., test whether program crashes
                 without sanitizers), "-- dotnet <arguments>" or "-- mono <arguments>" to
                 triage C# crashes with additional options

    Options:
      -l, --log-level <log-level>     Logging level [default: info] [possible values: info,
                                      debug]
      -j, --jobs <jobs>               Number of parallel jobs for generating CASR reports
                                      [default: half of cpu cores]
      -t, --timeout <SECONDS>         Timeout (in seconds) for target execution, 0 value means
                                      that timeout is disabled [default: 0]
      -i, --input <INPUT_DIR>         AFL++ work directory
      -o, --output <OUTPUT_DIR>       Output directory with triaged reports
          --join <PREV_CLUSTERS_DIR>  Use directory with previously triaged reports for new
                                      reports accumulation [env: CASR_PREV_CLUSTERS_DIR=]
      -f, --force-remove              Remove output project directory if it exists
          --ignore-cmdline            Force <ARGS> usage to run target instead of searching
                                      for cmdline files in AFL fuzzing directory
          --no-cluster                Do not cluster CASR reports
          --hint <HINT>               Hint to force run casr-HINT tool to analyze crashes
                                      [default: auto] [possible values: auto, gdb, san,
                                      csharp]
      -h, --help                      Print help
      -V, --version                   Print version

`casr-afl` provides a straightforward CASR integration with AFL++. While walking through afl
instances, `casr-afl` generates crash reports depending on target binary. For
binary with ASAN `casr-san` is used, otherwise `casr-gdb`. On the next step report
deduplication is done by `casr-cluster`. Finally, reports are traiged into
clusters. Crash reports contain many useful information: severity
(like [exploitable](https://github.com/jfoote/exploitable)), OS and package
versions, command line, stack trace, register values, disassembly, and even
source code fragment where crash appeared. `casr-afl` also provides integration with AFL-based
fuzzer [Sharpfuzz](https://github.com/Metalnem/sharpfuzz).

**NOTE:** `casr-gdb` and `casr-san` should be in PATH to make `casr-afl` work.

AFL++ Example (Ubuntu 20.04+):

    $ cp casr/tests/casr_tests/bin/load_afl /tmp/load_afl
    $ cp casr/tests/casr_tests/bin/load_sydr /tmp/load_sydr
    $ casr-afl -i casr/tests/casr_tests/casrep/afl-out-xlnt -o casr/tests/tmp_tests_casr/casr_afl_out

    $ tree tests/tmp_tests_casr/casr_afl_out
    tests/tmp_tests_casr/casr_afl_out
    ├── cl1
    │   └── id:000029,sig:00,src:000260,time:5748120,execs:122586,op:havoc,rep:8.casrep
    ├── cl10
    │   └── id:000002,sig:00,sync:afl_s01-worker,src:000136.casrep
    ├── cl11
    │   └── id:000024,sig:00,src:000507,time:1813906,execs:45610,op:havoc,rep:2.casrep
    ├── cl12
    │   ├── id:000016,sig:06,src:000018+000639,time:193966,execs:10509,op:splice,rep:2.casrep
    │   └── id:000018,sig:06,src:000064+000617,time:5061657,execs:49612,op:splice,rep:16.gdb.casrep
    ├── cl13
    │   ├── id:000017,sig:00,src:000048,time:665607,execs:21500,op:havoc,rep:8.gdb.casrep
    │   └── id:000019,sig:00,src:000064+000142,time:5072767,execs:49687,op:splice,rep:8.gdb.casrep
    ├── cl14
    │   └── id:000013,sig:00,sync:afl_main-worker,src:000791.gdb.casrep
    ├── cl15
    │   ├── id:000003,sig:00,sync:afl_main-worker,src:000152.gdb.casrep
    │   ├── id:000008,sig:00,sync:afl_main-worker,src:000510.gdb.casrep
    │   └── id:000011,sig:00,sync:afl_main-worker,src:000684.gdb.casrep
    ├── cl16
    │   ├── id:000015,sig:06,src:000667,time:147636,execs:9735,op:havoc,rep:4.gdb.casrep
    │   └── id:000019,sig:06,src:000040+000503,time:303958,execs:13059,op:splice,rep:8.casrep
    ├── cl17
    │   └── id:000004,sig:00,sync:afl_main-worker,src:000180.gdb.casrep
    ├── cl18
    │   └── id:000001,sig:00,sync:afl_main-worker,src:000111.gdb.casrep
    ├── cl19
    │   └── id:000025,sig:00,src:000405,time:14413049,execs:142946,op:havoc,rep:16.gdb.casrep
    ├── cl2
    │   └── id:000025,sig:00,sync:sydr-worker,src:000157.casrep
    ├── cl20
    │   └── id:000005,sig:00,sync:afl_main-worker,src:000335.gdb.casrep
    ├── cl21
    │   └── id:000028,sig:06,src:000204,time:5134989,execs:109591,op:havoc,rep:2.casrep
    ├── cl3
    │   ├── id:000009,sig:00,sync:afl_s01-worker,src:000560.casrep
    │   ├── id:000012,sig:00,sync:afl_s01-worker,src:000730.casrep
    │   ├── id:000013,sig:00,sync:afl_s01-worker,src:000791.casrep
    │   ├── id:000017,sig:00,src:000037,time:232885,execs:12235,op:havoc,rep:16.casrep
    │   └── id:000031,sig:00,sync:sydr-worker,src:000371.casrep
    ├── cl4
    │   └── id:000023,sig:00,src:000327,time:1245203,execs:33583,op:havoc,rep:16.casrep
    ├── cl5
    │   └── id:000015,sig:00,src:000018+000616,time:190597,execs:10485,op:splice,rep:16.casrep
    ├── cl6
    │   ├── id:000020,sig:00,src:000074+000118,time:448203,execs:16610,op:splice,rep:2.casrep
    │   ├── id:000022,sig:00,src:000178,time:654188,execs:21734,op:havoc,rep:16.casrep
    │   └── id:000030,sig:00,src:000375,time:24443406,execs:524127,op:havoc,rep:4.casrep
    ├── cl7
    │   ├── id:000000,sig:00,sync:afl_s01-worker,src:000025.casrep
    │   ├── id:000008,sig:00,sync:afl_s01-worker,src:000510.casrep
    │   └── id:000010,sig:00,sync:afl_s01-worker,src:000580.casrep
    ├── cl8
    │   └── id:000004,sig:00,sync:afl_s01-worker,src:000180.casrep
    └── cl9
        └── id:000001,sig:00,sync:afl_s01-worker,src:000111.casrep

You may also run `casr-afl` with additional report generation for uninstrumented
binary with `casr-gdb`:

    $ casr-afl -i casr/tests/casr_tests/casrep/afl-out-xlnt -o casr/tests/tmp_tests_casr/casr_afl_out -- /tmp/load_sydr @@

Thus, `casr-afl` will generate GDB crash report for each unique ASAN crash. So,
you can estimate crash severity for program built without sanitizers.

You can set environment variable `RUST_BACKTRACE=(1|full)` for `casr-afl`. This
variable may be used by [casr-san](#casr-san).

Sharpfuzz example:

    $ cp -r casr/tests/casr_tests/csharp/test_casr_afl_csharp /tmp/test_casr_afl_csharp
    $ cp -r casr/tests/casr_tests/csharp/test_casr_afl_csharp_module /tmp/test_casr_afl_csharp_module
    $ dotnet publish /tmp/test_casr_afl_csharp/test_casr_afl_csharp.csproj -c Debug -o /tmp/test_casr_afl_csharp/bin
    $ casr-afl -i casr/tests/casr_tests/casrep/afl-out-sharpfuzz -o casr/tests/tmp_tests_casr/casr_afl_csharp_out

Sharpfuzz example (with --ignore-cmdline):

    $ cp -r casr/tests/casr_tests/csharp/test_casr_afl_csharp /tmp/test_casr_afl_csharp
    $ cp -r casr/tests/casr_tests/csharp/test_casr_afl_csharp_module /tmp/test_casr_afl_csharp_module
    $ dotnet publish /tmp/test_casr_afl_csharp/test_casr_afl_csharp.csproj -c Debug -o /tmp/test_casr_afl_csharp/bin
    $ casr-afl --ignore-cmdline -i casr/tests/casr_tests/casrep/afl-out-sharpfuzz -o casr/tests/tmp_tests_casr/casr_afl_csharp_out -- dotnet run --no-build --project /tmp/test_casr_afl_csharp/test_casr_afl_csharp.csproj @@

Sharpfuzz example (with vanilla AFL directory):

    $ cp -r casr/tests/casr_tests/csharp/test_casr_afl_csharp /tmp/test_casr_afl_csharp
    $ cp -r casr/tests/casr_tests/csharp/test_casr_afl_csharp_module /tmp/test_casr_afl_csharp_module
    $ dotnet publish /tmp/test_casr_afl_csharp/test_casr_afl_csharp.csproj -c Debug -o /tmp/test_casr_afl_csharp/bin
    $ casr-afl -i casr/tests/casr_tests/casrep/afl-out-sharpfuzz/afl_main-worker -o casr/tests/tmp_tests_casr/casr_afl_csharp_out -- dotnet run --no-build --project /tmp/test_casr_afl_csharp/test_casr_afl_csharp.csproj @@

**NOTE 1:** if you run `casr-afl` for Sharpfuzz pipeline using `--ignore-cmdline` with `dotnet run`, build
your project before (via `dotnet build` or `dotnet publish`) and specify `--no-build` option for `dotnet run`.

**NOTE 2:** if you run `casr-afl` for Sharpfuzz pipeline using vanilla AFL input directory, force your own run arguments via `-- <ARGS>`.

## casr-libfuzzer

Triage crashes found by libFuzzer based fuzzer
(C/C++/go-fuzz/Atheris/Jazzer/Jazzer.js/jsfuzz/luzer) or LibAFL based fuzzer

    Usage: casr-libfuzzer [OPTIONS] --output <OUTPUT_DIR> -- <ARGS>...

    Arguments:
      <ARGS>...  Add "-- ./fuzz_target <arguments>"

    Options:
      -l, --log-level <log-level>
              Logging level [default: info] [possible values: info, debug]
      -j, --jobs <jobs>
              Number of parallel jobs for generating CASR reports [default: half of cpu cores]
      -t, --timeout <SECONDS>
              Timeout (in seconds) for target execution, 0 means that timeout is disabled
              [default: 0]
      -i, --input <INPUT_DIR>
              Directory containing crashes found by libFuzzer or LibAFL [default: .]
      -o, --output <OUTPUT_DIR>
              Output directory with triaged reports
          --join <PREV_CLUSTERS_DIR>
              Use directory with previously triaged reports for new reports accumulation [env:
              CASR_PREV_CLUSTERS_DIR=]
      -f, --force-remove
              Remove output project directory if it exists
          --no-cluster
              Do not cluster CASR reports
          --casr-gdb-args <casr-gdb-args>
              Add "--casr-gdb-args './gdb_fuzz_target <arguments>'" to generate additional
              crash reports with casr-gdb (e.g., test whether program crashes without
              sanitizers)
          --hint <HINT>
              Hint to force run casr-HINT tool to analyze crashes [default: auto] [possible
              values: auto, gdb, java, js, python, san]
      -h, --help
              Print help
      -V, --version
              Print version

`casr-libfuzzer` provides integration with
[libFuzzer](https://www.llvm.org/docs/LibFuzzer.html) based fuzzers
(C/C++/[go-fuzz](https://github.com/dvyukov/go-fuzz)/[Atheris](https://github.com/google/atheris)/
[Jazzer](https://github.com/CodeIntelligenceTesting/jazzer)/[Jazzer.js](https://github.com/CodeIntelligenceTesting/jazzer.js)/
[jsfuzz](https://github.com/fuzzitdev/jsfuzz)/[luzer](https://github.com/ligurio/luzer))
or [LibAFL](https://github.com/AFLplusplus/LibAFL) based
[fuzzers](https://github.com/AFLplusplus/LibAFL/tree/main/fuzzers).
It is pretty much like `casr-afl`.

libFuzzer example:

    $ casr-libfuzzer -t 30 -i casr/tests/casr_tests/casrep/libfuzzer_crashes_xlnt -o casr/tests/tmp_tests_casr/casr_libfuzzer_out -- casr/tests/casr_tests/bin/load_fuzzer

You may also run `casr-libfuzzer` with additional report generation for non-instrumented
binary with `casr-gdb`:

    $ casr-libfuzzer -t 30 -i casr/tests/casr_tests/casrep/libfuzzer_crashes_xlnt -o casr/tests/tmp_tests_casr/casr_libfuzzer_out --casr-gdb-args 'casr/tests/casr_tests/bin/load_sydr @@' -- casr/tests/casr_tests/bin/load_fuzzer

Atheris example:

    $ unzip casr/tests/casr_tests/python/ruamel.zip
    $ casr-libfuzzer -i casr/tests/casr_tests/casrep/atheris_crashes_ruamel_yaml -o casr/tests/tmp_tests_casr/casr_libfuzzer_atheris_out -- casr/tests/casr_tests/python/yaml_fuzzer.py

Jazzer.js example (Jazzer.js installation [guide](https://github.com/CodeIntelligenceTesting/jazzer.js#quickstart)):

    $ unzip casr/tests/casr_tests/js/xml2js.zip -d xml2js
    $ mkdir -p casr/tests/tmp_tests_casr/xml2js_fuzzer_out
    $ cp casr/tests/casr_tests/js/test_casr_libfuzzer_jazzer_js_xml2js.js casr/tests/tmp_tests_casr/xml2js_fuzzer_out/xml2js_fuzzer.js
    $ sudo npm install xml2js
    $ sudo npm install --save-dev @jazzer.js/core
    $ casr-libfuzzer -i ./xml2js -o casr/tests/tmp_tests_casr/xml2js_fuzzer_out/out -- npx jazzer casr/tests/tmp_tests_casr/xml2js_fuzzer_out/xml2js_fuzzer.js

Luzer example:

    $ unzip casr/tests/casr_tests/lua/xml2lua.zip && cd xml2lua && luarocks --local build && cd .. && rm -rf xml2lua
    $ git clone https://github.com/azanegin/luzer.git && \
            cd luzer && git checkout 77642ba37430eded66d171a68d7e9c3f6347d625 && luarocks --local build && cd .. && rm -rf luzer
    $ mkdir -p casr/tests/tmp_tests_casr/casr_libfuzzer_luzer_out
    $ casr-libfuzzer -i casr/tests/casr_tests/casrep/luzer_crashes_xml2lua -o casr/tests/tmp_tests_casr/casr_libfuzzer_luzer_out -- casr/tests/casr_tests/lua/stdin_parse_xml.lua

LibAFL example:

    $ casr-libfuzzer -i casr/tests/casr_tests/casrep/test_libafl_crashes -o casr/tests/tmp_tests_casr/casr_libafl_out -- casr/tests/casr_tests/bin/test_libafl_fuzzer @@

You can set environment variable `RUST_BACKTRACE=(1|full)` for `casr-libfuzzer`. This
variable may be used by [casr-san](#casr-san).

## casr-dojo

Tool for uploading new and unique CASR reports to DefectDojo

    Usage: casr-dojo [OPTIONS] --url <URL> --token <TOKEN> --input <INPUT_DIR> <PARAMS>

    Arguments:
      <PARAMS>  TOML file with parameters for DefectDojo product, engagement, and test

    Options:
      -l, --log-level <log-level>  Logging level [default: info] [possible values: info,
                                   debug]
      -u, --url <URL>              DefectDojo base URL
      -t, --token <TOKEN>          DefectDojo API key
      -i, --input <INPUT_DIR>      Directory that is recursively searched for CASR reports
                                   (also, crash seeds and CASR GDB reports if they are
                                   present)
      -h, --help                   Print help
      -V, --version                Print version

`casr-dojo` provides a convenient way of uploading new and unique CASR reports
to [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) vulnerability
management system. The findings deduplication is the same as in `casr-cluster
-d` and based on filtered stack trace hashing for all CASR reports except UBSAN.
UBSAN reports deduplication is based on crash source file and line number.
The `casr-dojo` tool performs crash analysis by the following steps:

1. Fill the default values for required DefectDojo [API
   parameters](https://demo.defectdojo.org/api/v2/oa3/swagger-ui/). You may
   override most parameters in `PARAMS` [TOML](https://toml.io/en/) that is
   passed to `casr-dojo`. Moreover, you can provide a string value for
   `test.test_type` (instead of integer id as specified in [API
   reference](https://demo.defectdojo.org/api/v2/oa3/swagger-ui/)), and
   `casr-dojo` will get existing or create new corresponding `test_type`.
2. Get existing or create new DefectDojo product (i.e. project being fuzzed),
   engagement (i.e. fuzz target and/or corresponding CI job), and test (i.e.
   fuzzer that found bugs) with specified names (more details
   [here](https://documentation.defectdojo.com/usage/models/)).
3. Get all active, false positive, and out of scope findings from DefectDojo. We
   eager to skip uploading duplicate findings and avoid discovering the same
   false positives.
4. Compute
   [filtered](https://github.com/ispras/casr/blob/master/libcasr/src/constants.rs)
   stack trace hashes (or get crash lines for UBSAN reports) for downloaded
   findings.
5. Upload new CASR reports to DefectDojo that have unique filtered stack trace
   hashes (or unique crash lines for UBSAN reports). Each finding will have a
   generated description with CASR report
   fields like crash line, severity, error description, source, stack trace,
   etc. Furthermore, `casr-dojo` uploads CASR report, GDB CASR report (if
   `.gdb.casrep` exists), and crash seed files for corresponding finding.

Thus, you can have a single entry point (DefectDojo) for all the crashes you
analyze with CASR.

You must specify DefectDojo URL (`-u`) and API v2 Key (`-t`). `casr-dojo`
recursively searches for all `.casrep` files in input directory (`-i`).
[Parameters](https://demo.defectdojo.org/api/v2/oa3/swagger-ui/) for DefectDojo
[entities](https://documentation.defectdojo.com/usage/models/) are specified in
[TOML](https://toml.io/en/) (`PARAMS`):

```toml
[product]
name = "xlnt"

[engagement]
name = "load_fuzzer 2023-06-07T16:47:18+03:00"

[test]
test_type = "CASR DAST Report"
```

CASR must be built with `dojo` feature via `cargo install -F dojo casr` or
`cargo build -F dojo --release`.

DefectDojo installation instructions can be found
[here](https://github.com/DefectDojo/django-DefectDojo/blob/dev/readme-docs/DOCKER.md).
The following commands can be used for a quick start:

    $ git clone https://github.com/DefectDojo/django-DefectDojo.git
    $ cd django-DefectDojo
    $ ./dc-build.sh
    $ ./dc-up.sh
    $ # Wait for complete initialization: django-defectdojo_initializer_1 exited with code 0
    $ # Get password for user "admin":
    $ docker-compose logs initializer | grep "Admin password:"

Upload new and unique CASR reports to
[DefectDojo](https://github.com/DefectDojo/django-DefectDojo):

    $ echo '[product]' > dojo.toml
    $ echo 'name = "xlnt"' >> dojo.toml
    $ echo '[engagement]' >> dojo.toml
    $ echo "name = \"load_fuzzer $(date -Isec)\"" >> dojo.toml
    $ echo '[test]' >> dojo.toml
    $ echo 'test_type = "CASR DAST Report"' >> dojo.toml
    $ casr-dojo -i casr/tests/casr_tests/casrep/test_clustering_san -u http://localhost:8080 -t 382f5dfdf2a339f7c3bb35442f9deb9b788a98d5 dojo.toml

### Screenshots

![dashboard](/docs/images/casr_dojo_dashboard.png)

![product](/docs/images/casr_dojo_product.png)

![findings](/docs/images/casr_dojo_findings.png)

![finding](/docs/images/casr_dojo_finding.png)

![finding-files](/docs/images/casr_dojo_finding_files.png)
