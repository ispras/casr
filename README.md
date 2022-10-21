# CASR: Crash Analysis and Severity Report

CASR &ndash; collect crash reports, triage, and estimate severity.
It is based on ideas from [exploitable](https://github.com/jfoote/exploitable) and
[apport](https://github.com/canonical/apport).

CASR is maintained by:

* [Andrey Fedotov](https://github.com/anfedotoff) \<fedotoff@ispras.ru\>
* [Alexey Vishnyakov](https://github.com/SweetVishnya) \<vishnya@ispras.ru\>
* [Georgy Savidov](https://github.com/Avgor46) \<avgor46@ispras.ru\>

## Overview

CASR is a set of tools that allows you to collect crash reports in different
ways. Use `casr` binary to deal with coredumps. Use `casr-san` to analyze ASAN
reports. Try `casr-gdb` to get reports from gdb.

Crash report contains many useful information: severity (like [exploitable](https://github.com/jfoote/exploitable)),
OS and package versions, command line, stack trace, register values,
disassembly, and even source code fragment where crash appeared. Reports are
stored in JSON format. `casr-cli` is meant to provide TUI for viewing reports.
Reports triage (deduplication, clustering) is done by `casr-cluster`.
Triage is based on stack trace comparison from [gdb-command](https://github.com/anfedotoff/gdb-command).

Explanation of severity classes could be found [here](docs/classes.md).
You could take a closer look at usage details [here](docs/usage.md).

![casr_report](docs/images/casr_report.png)

## Getting started

1. Install Rust. Instructions can be found [here](https://www.rust-lang.org/tools/install).
2. Clone CASR repository:

```
$ git clone https://github.com/ispras/casr
```
3. Build CASR:

```
$ cargo build --release
```
4. Install runtime dependencies:

```
$ sudo apt install gdb python3 python3-pip lsb-release
$ sudo -H python3 -m pip install numpy scipy
```

Instead of steps 2-3 you may just install Casr from crates.io:

    $ cargo install casr

## Usage

Create report from coredump:

    $ casr -f tests/casr_tests/bin/core.test_destAv -e tests/casr_tests/bin/test_destAv -o destAv.casrep

Create report from sanitizers output:

    $ clang++ -fsanitize=address -O0 -g tests/casr_tests/test_asan_df.cpp -o test_asan_df
    $ casr-san -o asan.casrep -- ./test_asan_df

Create report from gdb:

    $ casr-gdb -o destAv.gdb.casrep -- tests/casr_tests/bin/test_destAv $(printf 'A%.s' {1..200})

View report:

    $ casr-cli tests/casr_tests/casrep/test_clustering_san/load_fuzzer_crash-120697a7f5b87c03020f321c8526adf0f4bcc2dc.casrep

Create report for program that reads stdin:

    $ casr-san --stdin seed -o san_bin.casrep -- ./san_bin

Deduplicate reports:

    $ casr-cluster -d tests/casr_tests/casrep/test_clustering_gdb out-dedup

Cluster reports:

    $ casr-cluster -c out-dedup out-cluster

## Fuzzing Crash Triage Pipeline

When you have crashes from fuzzing you may do the following steps:

1. Create reports for all crashes via `casr-san` or `casr-gdb` (if no sanitizers
   are present).
2. Deduplicate collected reports via `casr-cluster -d`.
3. Cluster deduplicated reports via `casr-cluster -c`.
4. View reports from clusters using `casr-cli`.

## Contributing

Feel free to open issues or PRs! We appreciate your support!

Please follow the next recommendations for your pull requests:

- compile with *stable* rust
- use `cargo fmt`
- check the output of `cargo clippy --all`
- run tests `cargo test`

## Cite Us

Savidov G., Fedotov A. Casr-Cluster: Crash Clustering for Linux Applications. 2021 Ivannikov ISPRAS Open Conference (ISPRAS), IEEE, 2021, pp. 47-51. DOI: [10.1109/ISPRAS53967.2021.00012](https://www.doi.org/10.1109/ISPRAS53967.2021.00012) \[[paper](https://arxiv.org/abs/2112.13719)\] \[[slides](https://sydr-fuzz.github.io/papers/casr-cluster.pdf)\]

```bibtex
@inproceedings{savidov2021casr,
  title = {{{Casr-Cluster}}: Crash Clustering for Linux Applications},
  author = {Savidov, Georgy and Fedotov, Andrey},
  booktitle = {2021 Ivannikov ISPRAS Open Conference (ISPRAS)},
  pages = {47--51},
  year = {2021},
  organization = {IEEE},
  doi = {10.1109/ISPRAS53967.2021.00012},
}
```

## License

Licensed under [Apache-2.0](LICENSE).
