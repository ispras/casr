# Usage

CASR is a set of tools that allows you to collect crash reports in different
ways. Use `casr` binary to deal with coredumps. Use `casr-san` to analyze ASAN
reports. Try `casr-gdb` to get reports from gdb. `casr-cli` is meant to provide
TUI for viewing reports. Reports triage (deduplication, clustering) is done by
`casr-cluster`.

## casr-gdb

Create CASR reports (.casrep) from gdb execution

    USAGE:
        casr-gdb [OPTIONS] <--stdout|--output <REPORT>> [-- <ARGS>...]

    ARGS:
        <ARGS>...    Add "-- ./binary <arguments>" to run executable

    OPTIONS:
        -h, --help               Print help information
        -o, --output <REPORT>    Path to save report. Path can be a directory, then report
                                 name is generated
            --stdin <FILE>       Stdin file for program
            --stdout             Print CASR report to stdout
        -V, --version            Print version information

Example:

    $ casr-gdb -o destAv.gdb.casrep -- tests/casr_tests/bin/test_destAv $(printf 'A%.s' {1..200})

## casr-san

Create CASR reports (.casrep) from sanitizer reports

    USAGE:
        casr-san [OPTIONS] <--stdout|--output <REPORT>> [-- <ARGS>...]

    ARGS:
        <ARGS>...    Add "-- ./binary <arguments>" to run executable

    OPTIONS:
        -h, --help               Print help information
        -o, --output <REPORT>    Path to save report. Path can be a directory, then report
                                 name is generated
            --stdin <FILE>       Stdin file for program
            --stdout             Print CASR report to stdout
        -V, --version            Print version information

Compile binary with ASAN:

    $ clang++ -fsanitize=address -O0 -g tests/casr_tests/test_asan_df.cpp -o test_asan_df

Run casr-san:

    $ casr-san -o asan.casrep -- ./test_asan_df

## casr

Analyze coredump for security goals and provide detailed report with severity
estimation

    USAGE:
        casr [OPTIONS]

    OPTIONS:
        -e, --executable <FILE>    Path to executable
        -f, --file <FILE>          Path to input core file
        -h, --help                 Print help information
        -m, --mode <MODE>          Offline mode analyzes collected coredumps, online mode
                                   intercepts coredumps via core_pattern [default: offline]
                                   [possible values: online, offline]
        -o, --output <FILE>        Path to save report in JSON format
            --stdout               Print CASR report to stdout
        -V, --version              Print version information

`casr` have two modes: offline and online. Offline mode is used by default. You
may create report when you already have a coredump file.

Example:

    $ casr -f tests/casr_tests/bin/core.test_destAv -e tests/casr_tests/bin/test_destAv -o destAv.casrep

In online mode `casr` could intercept crashes via core\_pattern. You
should do the following steps.

Create directory `/var/crash` and set permissions for it:

    $ sudo mkdir -m 777 /var/crash

Update core\_pattern:

    $ echo "|<path_to_casr_binary> -m online -c %c -p %p  -P %P -u %u -g %g -e %E" | sudo tee /proc/sys/kernel/core_pattern

Set core ulimit to unlimited or another non-zero value:

    $ ulimit -c unlimited

To test just crash some programs:

    $ cd tests/casr_tests/bin && ./run.sh

Reports and coredumps will be stored in `/var/crash` directory.

## casr-cluster

Tool for clustering CASR reports

    USAGE:
        casr-cluster [OPTIONS]

    OPTIONS:
        -c, --cluster <INPUT_DIR> <OUTPUT_DIR>...
                Cluster CASR reports. If two directories are set, clusters will be placed in
                the second directory. If one directory is provided, clusters will be placed
                there, but reports in this directory will not be deleted.

        -d, --deduplicate <INPUT_DIR> <OUTPUT_DIR>...
                Deduplicate CASR reports. If two directories are set, deduplicated reports are
                copied to the second directory. If one directory is provided, duplicated
                reports are deleted.

        -h, --help
                Print help information

        -j, --jobs <N>
                Number of parallel jobs to collect CASR reports

        -s, --similarity <CASREP1> <CASREP2>
                Similarity between two CASR reports

        -V, --version
                Print version information

Report deduplication and clustering is based on stack trace comparison from
[gdb-command](https://github.com/anfedotoff/gdb-command). The idea is to run
deduplication first to remove equal reports, then run clustering on remaining
reports.

Example:

    $ casr-cluster -d tests/casr_tests/casrep/test_clustering_gdb out-dedup
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

## casr-cli

App provides text-based user interface to view CASR reports

    USAGE:
        casr-cli [OPTIONS] <REPORT>

    ARGS:
        <REPORT>    CASR report file to view

    OPTIONS:
        -h, --help           Print help information
        -v, --view <MODE>    View mode [default: tree] [possible values: tree, slider, stdout]
        -V, --version        Print version information

There are three view modes: tree, slider (list), and stdout. In stdout mode
`casr-cli` prints text-based CASR report to stdout.

Example:

    $ casr-cli tests/casr_tests/casrep/test_clustering_san/load_fuzzer_crash-120697a7f5b87c03020f321c8526adf0f4bcc2dc.casrep
