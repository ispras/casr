# Contributing

Feel free to open [issues](https://github.com/ispras/casr/issues) or [PRs](https://github.com/ispras/casr/pulls) (especially pay attention to [help wanted](https://github.com/ispras/casr/issues?q=is%3Aopen+is%3Aissue+label%3A%22help+wanted%22) issues)! We appreciate your support!

Please follow the next recommendations for your pull requests:

- compile with *stable* rust
- use `cargo fmt`
- check the output of `cargo clippy --all-features --all --tests`
- run tests `cargo test --lib -- --test-threads 1` and `cargo test --package casr`
- if you have updated usage of any casr tool, you could simply run
  `update_usage.py` to change the `docs/usage.md` file properly
