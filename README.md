# CASR: Crash Analysis and Severity Report

CASR &ndash; collect crash reports, triage and estimate severity.
It is based on ideas from [exploitable](https://github.com/jfoote/exploitable) and
[apport](https://github.com/canonical/apport).

CASR is maintained by:

* [Andrey Fedotov](https://github.com/anfedotoff)  <fedotoff@ispras.ru>
* [Alexey Vishnyakov](https://github.com/SweetVishnya) <vishnya@ispras.ru>
* [Georgy Savidov](https://github.com/Avgor46) <avgor46@ispras.ru>

## Overview

CASR is a set of tools allows you to collect crash reports in a different ways.
To deal with coredumps use `casr` binary. To analyze ASAN reports use
`casr-san`. To get reports from gdb try `casr-gdb`.

Crash report contains many useful information: severity (like [exploitable](https://github.com/jfoote/exploitable)),
OS and package versions, command line, stack trace, register values and
disassembly or even source code fragment, where crash was happened. Reports are
stored in JSON format. `casr-cli` is meant to provide TUI for viewing reports.
Reports triage (deduplication, clustering) is done by `casr-cluster`.
Triage is based on stack trace comparison from [gdb-command](https://github.com/anfedotoff/gdb-command).

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
## Contributing

Feel free to open issues or PRs! We appreciate your support!

Please follow the next recommendations for your pull requests:

- compile with *stable* rust
- use `cargo fmt`
- check the output of `cargo clippy --all`

## Cite Us

```bibtex
@inproceedings{savidov2021casr,
  title={Casr-Cluster: Crash Clustering for Linux Applications},
  author={Savidov, Georgy and Fedotov, Andrey},
  booktitle={2021 Ivannikov Ispras Open Conference (ISPRAS)},
  pages={47--51},
  year={2021},
  organization={IEEE}
}
```
### License
Licensed under Apache-2.0
