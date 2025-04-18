[![Crates.io](https://img.shields.io/crates/v/casr)](https://crates.io/crates/casr)
[![Documentation](https://docs.rs/libcasr/badge.svg)](https://docs.rs/libcasr)
[![codecov](https://codecov.io/github/ispras/casr/graph/badge.svg?token=D9VY1WRWA7)](https://app.codecov.io/github/ispras/casr)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://github.com/ispras/casr/blob/master/LICENSE)

[![amd64](https://github.com/ispras/casr/actions/workflows/amd64.yml/badge.svg?branch=master)](https://github.com/ispras/casr/actions/workflows/amd64.yml)
[![aarch64](https://github.com/ispras/casr/actions/workflows/aarch64.yml/badge.svg?branch=master)](https://github.com/ispras/casr/actions/workflows/aarch64.yml)
[![riscv64](https://github.com/ispras/casr/actions/workflows/riscv64.yml/badge.svg?branch=master)](https://github.com/ispras/casr/actions/workflows/riscv64.yml)
[![darwin-arm64](https://github.com/ispras/casr/actions/workflows/darwin-arm64.yml/badge.svg?branch=master)](https://github.com/ispras/casr/actions/workflows/darwin-arm64.yml)
[![fuzzing](https://github.com/ispras/casr/actions/workflows/fuzzing.yml/badge.svg?branch=master)](https://github.com/ispras/casr/actions/workflows/fuzzing.yml)

# CASR: Crash Analysis and Severity Report

CASR &ndash; collect crash (or UndefinedBehaviorSanitizer error) reports, triage, and estimate severity.
It is based on ideas from [exploitable](https://github.com/jfoote/exploitable) and
[apport](https://github.com/canonical/apport).

CASR is maintained by:

* [Andrey Fedotov](https://github.com/anfedotoff) \<splashgitar@gmail.com\>
* [Alexey Vishnyakov](https://github.com/SweetVishnya) \<pmvishnya@gmail.com\>
* [Georgy Savidov](https://github.com/Avgor46) \<avgor46@ispras.ru\>
* [Ilya Yegorov](https://github.com/hkctkuy) \<hkctkuy@gmail.com\>
* [Darya Parygina](https://github.com/PaDarochek) \<pa_darochek@ispras.ru\>

## Overview

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
Use `casr-lua` to analyze Lua reports.

Crash report contains many useful information: severity (like [exploitable](https://github.com/jfoote/exploitable))
for x86, x86\_64, arm32, aarch64, rv32g, rv64g architectures,
OS and package versions, command line, stack trace, register values,
disassembly, and even source code fragment where crash appeared. Reports are
stored in JSON format. `casr-cli` is meant to provide TUI for viewing reports
and converting them into SARIF report.
Reports triage (deduplication, clustering) is done by `casr-cluster`.
Triage is based on stack trace comparison from [gdb-command](https://github.com/anfedotoff/gdb-command).
`casr-afl` is used to triage crashes found by [AFL++](https://github.com/AFLplusplus/AFLplusplus)
and AFL-based fuzzer [Sharpfuzz](https://github.com/Metalnem/sharpfuzz).
`casr-libfuzzer` can triage crashes found by
[libFuzzer](https://www.llvm.org/docs/LibFuzzer.html) based fuzzer
(C/C++/[go-fuzz](https://github.com/dvyukov/go-fuzz)/[Atheris](https://github.com/google/atheris)
/[Jazzer](https://github.com/CodeIntelligenceTesting/jazzer)/[Jazzer.js](https://github.com/CodeIntelligenceTesting/jazzer.js)/
[jsfuzz](https://github.com/fuzzitdev/jsfuzz)/[luzer](https://github.com/ligurio/luzer))
or [LibAFL](https://github.com/AFLplusplus/LibAFL)
based [fuzzers](https://github.com/AFLplusplus/LibAFL/tree/main/fuzzers).
`casr-dojo` allows to upload new and unique CASR reports to
[DefectDojo](https://github.com/DefectDojo/django-DefectDojo) (available with
`dojo` feature).

Explanation of severity classes could be found [here](docs/classes.md).
You could take a closer look at usage details [here](docs/usage.md).

![casr_report](docs/images/casr_report.png)

![casr_dojo_finding](/docs/images/casr_dojo_finding.png)

### LibCASR

LibCASR provides API for parsing stacktraces, collecting crash reports,
triaging crashes (deduplication and clustering), and estimating severity of
crashes.

It can analyze crashes from different sources:

* AddressSanitizer
* MemorySanitizer
* UndefinedBehaviorSanitizer
* Gdb output

and program languages:

* C/C++
* C#
* Go
* Java
* JavaScript
* Lua
* Python
* Rust

It could be built with `exploitable` feature for severity estimation crashes
collected from gdb. To save crash reports as json use `serde` feature.

## Dependencies

Install runtime dependencies:

    $ sudo apt install gdb lsb-release

Install build dependencies when building from source:

    $ sudo apt install build-essential clang

Install [Rust](https://www.rust-lang.org/tools/install) or update existing Rust installation:

    $ rustup update

## Install

Download latest Linux 64-bit
[release](https://github.com/ispras/casr/releases/latest/download/casr-x86_64-unknown-linux-gnu.tar.xz)
or build from source as explained below.

N.B. Current MacOS support is experimental. Some Linux-based code like
[exploitable](https://github.com/ispras/casr/blob/master/libcasr/src/gdb/exploitable.rs)
and `casr-gdb` may not properly work. Further contributions are very much
welcomed here.

Build from Git repository:

    $ git clone https://github.com/ispras/casr
    $ cargo update
    $ cargo build --release

Or you may just install Casr from [crates.io](https://crates.io/crates/casr):

    $ cargo install casr

Add `dojo` feature if you want to install `casr-dojo` (the same for `cargo build`):

    $ cargo install -F dojo casr

## Usage

**Running in Docker:** CASR disables address randomization for better
deduplication and uses ptrace to run GDB. Thus, Docker should be started with
`--cap-add=SYS_PTRACE --security-opt seccomp=unconfined`.

Create report from coredump:

    $ casr-core -f casr/tests/casr_tests/bin/core.test_destAv -e casr/tests/casr_tests/bin/test_destAv -o destAv.casrep

Create report from AddressSanitizer output:

    $ clang++ -fsanitize=address -O0 -g casr/tests/casr_tests/test_asan_df.cpp -o test_asan_df
    $ casr-san -o asan.casrep -- ./test_asan_df

Create report from MemorySanitizer output:

    $ clang++ -fsanitize=memory -O0 -g casr/tests/casr_tests/test_msan.cpp -o test_msan
    $ casr-san -o msan.casrep -- ./test_msan

Create report from UndefinedBehaviorSanitizer output:

    $ clang++ -fsanitize=undefined -O0 -g casr/tests/casr_tests/ubsan/test_ubsan.cpp -o test_ubsan
    $ casr-ubsan -i casr/tests/casr_tests/ubsan/input1 -o output -- ./test_ubsan @@
    $ casr-cli output

Create report from gdb:

    $ casr-gdb -o destAv.gdb.casrep -- casr/tests/casr_tests/bin/test_destAv $(printf 'A%.s' {1..200})

Create report from python:

    $ casr-python -o python.casrep -- casr/tests/casr_tests/python/test_casr_python.py

Create report from java:

    $ casr-java -o java.casrep -- java casr/tests/casr_tests/java/Test1.java

Create report from JavaScript:

    $ casr-js -o js.casrep -- node casr/tests/casr_tests/js/test_casr_js.js

Create report from C#:

    $ casr-csharp -o csharp.casrep -- dotnet run --project casr/tests/casr_tests/csharp/test_casr_csharp/test_casr_csharp.csproj

Create report from Lua:

    $ casr-lua -o lua.casrep -- casr/tests/casr_tests/lua/test_casr_lua.lua

View report:

    $ casr-cli casr/tests/casr_tests/casrep/test_clustering_san/load_fuzzer_crash-120697a7f5b87c03020f321c8526adf0f4bcc2dc.casrep

View joint statistics about crash clusters:

    $ casr-cli casr_reports

Convert reports to SARIF report:

    $ casr-cli --sarif out.sarif --tool libfuzzer --source-root /xlnt casr/tests/casr_tests/casrep/test_clustering_san

Create report for program that reads stdin:

    $ casr-san --stdin seed -o san_bin.casrep -- ./san_bin

Deduplicate reports:

    $ casr-cluster -d casr/tests/casr_tests/casrep/test_clustering_gdb out-dedup

Cluster reports:

    $ casr-cluster -c out-dedup out-cluster

Triage crashes after AFL++ fuzzing with casr-afl:

    $ cp casr/tests/casr_tests/bin/load_afl /tmp/load_afl
    $ cp casr/tests/casr_tests/bin/load_sydr /tmp/load_sydr
    $ casr-afl -i casr/tests/casr_tests/casrep/afl-out-xlnt -o casr/tests/tmp_tests_casr/casr_afl_out
    $ # You may also additionally generate crash reports for uninstrumented binary with casr-gdb
    $ casr-afl -i casr/tests/casr_tests/casrep/afl-out-xlnt -o casr/tests/tmp_tests_casr/casr_afl_out -- /tmp/load_sydr @@

Triage crashes after Sharpfuzz fuzzing with casr-afl:

    $ cp -r casr/tests/casr_tests/csharp/test_casr_afl_csharp /tmp/test_casr_afl_csharp
    $ cp -r casr/tests/casr_tests/csharp/test_casr_afl_csharp_module /tmp/test_casr_afl_csharp_module
    $ dotnet publish /tmp/test_casr_afl_csharp/test_casr_afl_csharp.csproj -c Debug -o /tmp/test_casr_afl_csharp/bin
    $ casr-afl -i casr/tests/casr_tests/casrep/afl-out-sharpfuzz -o casr/tests/tmp_tests_casr/casr_afl_csharp_out
    $ # You may force your own run arguments using --ignore-cmdline
    $ casr-afl --ignore-cmdline -i casr/tests/casr_tests/casrep/afl-out-sharpfuzz -o casr/tests/tmp_tests_casr/casr_afl_csharp_out -- dotnet run --no-build --project /tmp/test_casr_afl_csharp/test_casr_afl_csharp.csproj @@
    $ # If you use vanilla AFL for fuzzing with Sharpfuzz, force your own run arguments via -- <ARGS>
    $ casr-afl -i casr/tests/casr_tests/casrep/afl-out-sharpfuzz/afl_main-worker -o casr/tests/tmp_tests_casr/casr_afl_csharp_out -- dotnet run --no-build --project /tmp/test_casr_afl_csharp/test_casr_afl_csharp.csproj @@

Triage libFuzzer crashes with casr-libfuzzer:

    $ casr-libfuzzer -t 30 -i casr/tests/casr_tests/casrep/libfuzzer_crashes_xlnt -o casr/tests/tmp_tests_casr/casr_libfuzzer_out -- casr/tests/casr_tests/bin/load_fuzzer

Triage Atheris crashes with casr-libfuzzer:

    $ unzip casr/tests/casr_tests/python/ruamel.zip
    $ casr-libfuzzer -i casr/tests/casr_tests/casrep/atheris_crashes_ruamel_yaml -o casr/tests/tmp_tests_casr/casr_libfuzzer_atheris_out -- casr/tests/casr_tests/python/yaml_fuzzer.py

Triage Jazzer.js crashes with casr-libfuzzer (Jazzer.js installation [guide](https://github.com/CodeIntelligenceTesting/jazzer.js#quickstart)):

    $ unzip casr/tests/casr_tests/js/xml2js.zip -d xml2js
    $ mkdir -p casr/tests/tmp_tests_casr/xml2js_fuzzer_out
    $ cp casr/tests/casr_tests/js/test_casr_libfuzzer_jazzer_js_xml2js.js casr/tests/tmp_tests_casr/xml2js_fuzzer_out/xml2js_fuzzer.js
    $ sudo npm install xml2js
    $ sudo npm install --save-dev @jazzer.js/core
    $ casr-libfuzzer -i ./xml2js -o casr/tests/tmp_tests_casr/xml2js_fuzzer_out/out -- npx jazzer casr/tests/tmp_tests_casr/xml2js_fuzzer_out/xml2js_fuzzer.js

Triage luzer crashes with casr-libfuzzer:

    $ unzip casr/tests/casr_tests/lua/xml2lua.zip && cd xml2lua && luarocks --local build && cd .. && rm -rf xml2lua
    $ git clone https://github.com/ligurio/luzer.git && cd luzer && luarocks --local build && cd .. && rm -rf luzer
    $ eval $(luarocks path)
    $ casr-libfuzzer -i casr/tests/casr_tests/casrep/luzer_crashes_xml2lua -o casr/tests/tmp_tests_casr/casr_libfuzzer_luzer_out -- casr/tests/casr_tests/lua/stdin_parse_xml.lua

Triage LibAFL crashes with casr-libfuzzer:

    $ casr-libfuzzer -i casr/tests/casr_tests/casrep/test_libafl_crashes -o casr/tests/tmp_tests_casr/casr_libafl_out -- casr/tests/casr_tests/bin/test_libafl_fuzzer @@

Upload new and unique CASR reports to
[DefectDojo](https://github.com/DefectDojo/django-DefectDojo):

    $ echo '[product]' > dojo.toml
    $ echo 'name = "xlnt"' >> dojo.toml
    $ echo '[engagement]' >> dojo.toml
    $ echo "name = \"load_fuzzer $(date -Isec)\"" >> dojo.toml
    $ echo '[test]' >> dojo.toml
    $ echo 'test_type = "CASR DAST Report"' >> dojo.toml
    $ casr-dojo -i casr/tests/casr_tests/casrep/test_clustering_san -u http://localhost:8080 -t 382f5dfdf2a339f7c3bb35442f9deb9b788a98d5 dojo.toml

## Fuzzing Crash Triage Pipeline

When you have crashes from fuzzing you may do the following steps:

1. Create reports for all crashes via `casr-san`, `casr-gdb` (if no sanitizers
   are present), `casr-python`, `casr-java`, `casr-js`, or `casr-csharp`.
2. Deduplicate collected crash reports via `casr-cluster -d`.
3. Cluster deduplicated crash reports via `casr-cluster -c`.
4. Create reports and deduplicate them for all UBSAN errors via `casr-ubsan`.
5. View reports from clusters using `casr-cli` or upload them to
   [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) with
   `casr-dojo`.

If you use [AFL++](https://github.com/AFLplusplus/AFLplusplus) or AFL-based
fuzzer [Sharpfuzz](https://www.llvm.org/docs/LibFuzzer.html), the pipeline
(without `casr-ubsan` and `casr-dojo`) could be done automatically by
`casr-afl`.

If you use [libFuzzer](https://www.llvm.org/docs/LibFuzzer.html) based fuzzer
(C/C++/[go-fuzz](https://github.com/dvyukov/go-fuzz)/[Atheris](https://github.com/google/atheris)
/[Jazzer](https://github.com/CodeIntelligenceTesting/jazzer)/[Jazzer.js](https://github.com/CodeIntelligenceTesting/jazzer.js)/
[jsfuzz](https://github.com/fuzzitdev/jsfuzz)) or [LibAFL](https://github.com/AFLplusplus/LibAFL) based fuzzer,
the pipeline (without `casr-ubsan` and `casr-dojo`) could be done automatically by `casr-libfuzzer`.

## Contributing

Feel free to open [issues](https://github.com/ispras/casr/issues) or [PRs](https://github.com/ispras/casr/pulls) (especially pay attention to [help wanted](https://github.com/ispras/casr/issues?q=is%3Aopen+is%3Aissue+label%3A%22help+wanted%22) issues)! We appreciate your support!

Please follow the next recommendations for your pull requests:

- compile with *stable* rust
- use `cargo fmt`
- check the output of `cargo clippy --all-features --all --tests`
- run tests `cargo test`
- if you have updated usage of any casr tool, you could simply run
  `update_usage.py` to change the `docs/usage.md` file properly

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

Andrey Fedotov, Alexey Vishnyakov. CASR: Your Life Vest in a Sea of Crashes. OFFZONE 2023. \[[slides](https://vishnya.xyz/mirror/casr-offzone2023.pdf)\] \[[russian&nbsp;video](https://youtu.be/EgEeICZQD9M?si=hiFEwPmDqnh0cEq6)\]

Yegorov I., Savidov G. Crash Report Accumulation During Continuous Fuzzing with CASR. Ivannikov Memorial Workshop 2024, IEEE, 2024. \[[paper](https://arxiv.org/abs/2405.18174)\] \[[slides](https://sydr-fuzz.github.io/papers/crash-accumulation.pdf)\] \[[russian&nbsp;video](https://www.youtube.com/live/xI1LQS3C7eQ?si=dHNdm4-nZFc2QdQf&t=27620)\]

```bibtex
@inproceedings{yegorov2024accum,
  title = {Crash Report Accumulation During Continuous Fuzzing},
  author = {Yegorov, Ilya and Savidov, Georgy},
  booktitle = {Ivannikov Memorial Workshop 2024},
  publisher = {IEEE},
  year = {2024},
  url = {https://arxiv.org/abs/2405.18174},
}
```

## License

Licensed under [Apache-2.0](LICENSE).
