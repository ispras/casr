//! # CASR: Crash Analysis and Severity Report
//!
//! CASR &ndash; collect crash reports, triage, and estimate severity.
//! It is based on ideas from [exploitable](https://github.com/jfoote/exploitable) and
//! [apport](https://github.com/canonical/apport).
//!
//! Enable `dojo` feature to build `casr-dojo` that can upload new and unique
//! CASR reports to [DefectDojo](https://github.com/DefectDojo/django-DefectDojo).

pub mod analysis;
pub mod util;
