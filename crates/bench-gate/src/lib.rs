//! CI gate for criterion benchmark results (S7 — docs/04-performance.md).
//!
//! Reads criterion's machine-readable output directly —
//! `<criterion>/throughput/push/<corpus>/new/{benchmark,estimates}.json` —
//! instead of parsing criterion's human stdout. The persisted numbers are
//! unit-free (nanoseconds, bytes), so the throughput-unit scaling that broke
//! the previous stdout-regex parser (KiB/s → MiB/s → GiB/s) cannot occur
//! here by construction.
//!
//! Three operations, mirroring the nightly bench-floor job:
//! - [`check_floor`]: the worse of the two clean corpora must meet the floor.
//! - [`check_regression`]: no benchmark may regress beyond a threshold
//!   against a stored baseline ([`Baseline`]).
//! - [`make_baseline`]: emit a baseline from the current run.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Gate failure with a CI-log-ready message.
#[derive(Debug)]
pub struct GateError(pub String);

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for GateError {}

/// One measured benchmark: criterion's median iteration time plus the
/// bytes-per-iteration the bench declared via `Throughput::Bytes`.
#[derive(Debug, Clone, PartialEq)]
pub struct BenchSample {
    /// Criterion's full benchmark id, e.g. `throughput/push/clean-text`.
    pub id: String,
    /// Median iteration time in nanoseconds (criterion's median point
    /// estimate — the same number criterion prints in its thrpt line).
    pub median_ns: f64,
    /// Bytes processed per iteration (the corpus size).
    pub bytes: u64,
}

impl BenchSample {
    /// Throughput in MB/s (10⁶ bytes/s) — the unit the floor gate uses.
    pub fn mbs(&self) -> f64 {
        self.bytes as f64 * 1e3 / self.median_ns
    }

    /// Throughput in MiB/s (2²⁰ bytes/s) — the unit baselines store.
    pub fn mibs(&self) -> f64 {
        self.bytes as f64 * 1e9 / self.median_ns / (1024.0 * 1024.0)
    }
}

// ── criterion output files ─────────────────────────────────────────────

/// `new/benchmark.json` — id and declared throughput.
#[derive(Deserialize)]
struct BenchmarkMeta {
    full_id: String,
    throughput: ThroughputField,
}

/// Criterion serializes `Throughput::Bytes(n)` as `{"Bytes": n}`.
#[derive(Deserialize)]
enum ThroughputField {
    Bytes(u64),
}

/// `new/estimates.json` — only the median point estimate is needed.
#[derive(Deserialize)]
struct Estimates {
    median: Estimate,
}

#[derive(Deserialize)]
struct Estimate {
    point_estimate: f64,
}

/// Discover every `throughput/push/*` benchmark under the criterion dir.
///
/// Non-benchmark directories (e.g. criterion's `report/`) are skipped: a
/// directory counts only if both `new/benchmark.json` and
/// `new/estimates.json` are readable and parse.
pub fn discover(criterion_dir: &Path) -> Result<Vec<BenchSample>, GateError> {
    let push_dir = criterion_dir.join("throughput").join("push");
    let entries = fs::read_dir(&push_dir)
        .map_err(|e| GateError(format!("read {}: {e}", push_dir.display())))?;

    let mut samples = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|e| GateError(format!("read {}: {e}", push_dir.display())))?
            .path();
        let new_dir = path.join("new");
        let meta_raw = match fs::read(new_dir.join("benchmark.json")) {
            Ok(raw) => raw,
            Err(_) => continue, // not a benchmark result directory
        };
        let est_raw = fs::read(new_dir.join("estimates.json")).map_err(|e| {
            GateError(format!(
                "read {}: {e}",
                new_dir.join("estimates.json").display()
            ))
        })?;

        let meta: BenchmarkMeta = serde_json::from_slice(&meta_raw).map_err(|e| {
            GateError(format!(
                "parse {}: {e}",
                new_dir.join("benchmark.json").display()
            ))
        })?;
        let est: Estimates = serde_json::from_slice(&est_raw).map_err(|e| {
            GateError(format!(
                "parse {}: {e}",
                new_dir.join("estimates.json").display()
            ))
        })?;
        let ThroughputField::Bytes(bytes) = meta.throughput;

        samples.push(BenchSample {
            id: meta.full_id,
            median_ns: est.median.point_estimate,
            bytes,
        });
    }

    if samples.is_empty() {
        return Err(GateError(format!(
            "no throughput/push/* benchmarks found under {}",
            criterion_dir.display()
        )));
    }
    samples.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(samples)
}

// ── floor gate ─────────────────────────────────────────────────────────

/// Floor-gate outcome over the two clean corpora.
#[derive(Debug, PartialEq)]
pub struct FloorOutcome {
    pub clean_json_mbs: f64,
    pub clean_text_mbs: f64,
    /// The worse of the two — the gated number.
    pub worse_mbs: f64,
    pub passed: bool,
}

/// Assert the worse of `clean-json` / `clean-text` meets `floor_mbs`.
///
/// Errors if either clean corpus is missing from the samples — a missing
/// benchmark must fail the gate, not silently pass it.
pub fn check_floor(samples: &[BenchSample], floor_mbs: f64) -> Result<FloorOutcome, GateError> {
    let find = |suffix: &str| {
        samples
            .iter()
            .find(|s| s.id == format!("throughput/push/{suffix}"))
    };
    let (json, text) = (find("clean-json"), find("clean-text"));
    let (Some(json), Some(text)) = (json, text) else {
        let missing: Vec<&str> = [json.is_none(), text.is_none()]
            .into_iter()
            .zip(["clean-json", "clean-text"])
            .filter(|(m, _)| *m)
            .map(|(_, n)| n)
            .collect();
        return Err(GateError(format!(
            "missing benchmark(s) in criterion output: {missing:?}"
        )));
    };

    let (json_mbs, text_mbs) = (json.mbs(), text.mbs());
    let worse_mbs = json_mbs.min(text_mbs);
    Ok(FloorOutcome {
        clean_json_mbs: json_mbs,
        clean_text_mbs: text_mbs,
        worse_mbs,
        passed: worse_mbs >= floor_mbs,
    })
}

// ── regression gate ────────────────────────────────────────────────────

/// Stored regression baseline — the committed
/// `docs/benchmarks/baselines/<ARCH>.json` files. Unknown fields (e.g. the
/// hand-written `note`) are ignored on load.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Baseline {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rustc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default)]
    pub benchmarks: BTreeMap<String, BaselineEntry>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct BaselineEntry {
    pub median_mibs: f64,
}

/// Load a baseline; `Ok(None)` if the file does not exist (the caller warns
/// and skips — same semantics as the gate has always had). Malformed files
/// are hard errors: a broken baseline must fail loudly, not pass silently.
pub fn load_baseline(path: &Path) -> Result<Option<Baseline>, GateError> {
    let raw = match fs::read(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(GateError(format!("read {}: {e}", path.display()))),
    };
    let baseline: Baseline = serde_json::from_slice(&raw)
        .map_err(|e| GateError(format!("parse {} as baseline JSON: {e}", path.display())))?;
    Ok(Some(baseline))
}

/// Per-benchmark regression status.
#[derive(Debug, PartialEq)]
pub enum RegStatus {
    /// Within the threshold of the stored baseline.
    Ok,
    /// Regressed beyond the threshold — gate failure.
    Regressed,
    /// No stored baseline for this benchmark — informational only.
    NoBaseline,
}

/// One benchmark's regression check result.
#[derive(Debug, PartialEq)]
pub struct RegResult {
    pub id: String,
    pub current_mibs: f64,
    pub baseline_mibs: Option<f64>,
    /// Percentage change vs baseline; `None` when no baseline exists.
    pub change_pct: Option<f64>,
    pub status: RegStatus,
}

/// Compare every sample against the stored baseline. A benchmark regressed
/// when its median dropped more than `threshold_pct` below the baseline.
pub fn check_regression(
    samples: &[BenchSample],
    baseline: &Baseline,
    threshold_pct: f64,
) -> Result<Vec<RegResult>, GateError> {
    let mut results = Vec::new();
    for s in samples {
        let entry = baseline.benchmarks.get(&s.id);
        let (baseline_mibs, change_pct, status) = match entry {
            None => (None, None, RegStatus::NoBaseline),
            Some(e) => {
                let change_pct = (s.mibs() - e.median_mibs) / e.median_mibs * 100.0;
                let status = if change_pct > -threshold_pct {
                    RegStatus::Ok
                } else {
                    RegStatus::Regressed
                };
                (Some(e.median_mibs), Some(change_pct), status)
            }
        };
        results.push(RegResult {
            id: s.id.clone(),
            current_mibs: s.mibs(),
            baseline_mibs,
            change_pct,
            status,
        });
    }
    Ok(results)
}

/// Build a baseline from the current run's samples (the `emit-baseline`
/// command). `BTreeMap` keeps the serialization deterministic.
pub fn make_baseline(
    samples: &[BenchSample],
    target: &str,
    rustc: &str,
    generated: &str,
) -> Baseline {
    Baseline {
        generated: Some(generated.to_string()),
        rustc: Some(rustc.to_string()),
        target: Some(target.to_string()),
        note: None,
        benchmarks: samples
            .iter()
            .map(|s| {
                (
                    s.id.clone(),
                    BaselineEntry {
                        median_mibs: s.mibs(),
                    },
                )
            })
            .collect(),
    }
}

// ── date helper (no chrono — one well-known algorithm) ─────────────────

/// Civil date from days since the Unix epoch (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (y + i64::from(m <= 2), m, d)
}

/// Today's date as `YYYY-MM-DD` (UTC). Metadata for emitted baselines.
pub fn today_iso() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real criterion run from the receipts: clean-text,
    /// 1,048,653 bytes, median 3,728,216.7 ns → 281.3 MB/s / 268.2 MiB/s.
    fn clean_text_sample() -> BenchSample {
        BenchSample {
            id: "throughput/push/clean-text".to_string(),
            median_ns: 3_728_216.7,
            bytes: 1_048_653,
        }
    }

    fn sample(id: &str, median_ns: f64, bytes: u64) -> BenchSample {
        BenchSample {
            id: format!("throughput/push/{id}"),
            median_ns,
            bytes,
        }
    }

    // ── throughput math ────────────────────────────────────────────────

    #[test]
    fn mbs_known_value() {
        assert!(
            (clean_text_sample().mbs() - 281.3).abs() < 0.1,
            "{}",
            clean_text_sample().mbs()
        );
    }

    #[test]
    fn mibs_known_value() {
        assert!(
            (clean_text_sample().mibs() - 268.2).abs() < 0.1,
            "{}",
            clean_text_sample().mibs()
        );
    }

    // ── discovery ─────────────────────────────────────────────────────

    /// Write a fake criterion result directory: one benchmark under
    /// `<dir>/throughput/push/<name>/new/`.
    fn write_fake_bench(root: &Path, name: &str, median_ns: f64, bytes: u64) {
        let new_dir = root.join("throughput").join("push").join(name).join("new");
        fs::create_dir_all(&new_dir).unwrap();
        let meta = format!(
            r#"{{"group_id":"throughput","function_id":"push","value_str":"{name}","throughput":{{"Bytes":{bytes}}},"full_id":"throughput/push/{name}","directory_name":"throughput/push/{name}","title":"throughput/push/{name}"}}"#
        );
        let est = format!(
            r#"{{"mean":{{"point_estimate":{median_ns}}},"median":{{"confidence_interval":{{"confidence_level":0.95,"lower_bound":1.0,"upper_bound":2.0}},"point_estimate":{median_ns},"standard_error":0.1}}}}"#
        );
        fs::write(new_dir.join("benchmark.json"), meta).unwrap();
        fs::write(new_dir.join("estimates.json"), est).unwrap();
    }

    #[test]
    fn discover_finds_benchmarks_and_skips_non_results() {
        let root = tempfile::tempdir().unwrap();
        write_fake_bench(root.path(), "clean-json", 2_800_000.0, 1_048_644);
        write_fake_bench(root.path(), "clean-text", 3_728_216.7, 1_048_653);
        // criterion's report dir — no new/*.json, must be skipped.
        fs::create_dir_all(root.path().join("throughput").join("push").join("report")).unwrap();

        let samples = discover(root.path()).unwrap();
        assert_eq!(samples.len(), 2);
        // Sorted by id.
        assert_eq!(samples[0].id, "throughput/push/clean-json");
        assert_eq!(samples[1].id, "throughput/push/clean-text");
        assert!((samples[1].mbs() - 281.3).abs() < 0.1);
    }

    #[test]
    fn discover_missing_dir_is_an_error() {
        let err = discover(Path::new("/nonexistent/criterion")).unwrap_err();
        assert!(err.0.contains("read"), "{err}");
    }

    #[test]
    fn discover_no_benchmarks_is_an_error() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("throughput").join("push")).unwrap();
        let err = discover(root.path()).unwrap_err();
        assert!(err.0.contains("no throughput/push"), "{err}");
    }

    #[test]
    fn discover_malformed_estimates_is_an_error() {
        let root = tempfile::tempdir().unwrap();
        write_fake_bench(root.path(), "clean-json", 1.0, 100);
        let est = root
            .path()
            .join("throughput")
            .join("push")
            .join("clean-json")
            .join("new");
        fs::write(est.join("estimates.json"), "not json").unwrap();
        let err = discover(root.path()).unwrap_err();
        assert!(err.0.contains("parse"), "{err}");
    }

    // ── floor gate ─────────────────────────────────────────────────────

    fn clean_samples() -> Vec<BenchSample> {
        vec![
            sample("clean-json", 2_800_000.0, 1_048_644),
            sample("clean-text", 3_728_216.7, 1_048_653),
        ]
    }

    #[test]
    fn floor_passes_when_worse_corpus_meets_it() {
        // clean-text ≈ 281.3 MB/s is the worse one.
        let outcome = check_floor(&clean_samples(), 250.0).unwrap();
        assert!(outcome.passed);
        assert!((outcome.worse_mbs - 281.3).abs() < 0.1);
    }

    #[test]
    fn floor_fails_when_worse_corpus_misses_it() {
        let outcome = check_floor(&clean_samples(), 500.0).unwrap();
        assert!(!outcome.passed);
    }

    #[test]
    fn floor_missing_clean_corpus_is_an_error() {
        let samples = vec![
            sample("clean-json", 1.0, 100),
            sample("dirty-mixed", 1.0, 100),
        ];
        let err = check_floor(&samples, 250.0).unwrap_err();
        assert!(err.0.contains("clean-text"), "{err}");
    }

    // ── regression gate ───────────────────────────────────────────────

    fn baseline_with(entries: &[(&str, f64)]) -> Baseline {
        Baseline {
            benchmarks: entries
                .iter()
                .map(|(id, mibs)| {
                    (
                        format!("throughput/push/{id}"),
                        BaselineEntry { median_mibs: *mibs },
                    )
                })
                .collect(),
            ..Baseline::default()
        }
    }

    #[test]
    fn regression_ok_within_threshold() {
        // Current 268.2 MiB/s vs baseline 260 → +3.2%, within 10%.
        let baseline = baseline_with(&[("clean-text", 260.0)]);
        let results = check_regression(&clean_samples(), &baseline, 10.0).unwrap();
        assert_eq!(results[1].status, RegStatus::Ok);
        assert!((results[1].change_pct.unwrap() - 3.2).abs() < 0.1);
    }

    #[test]
    fn regression_fails_beyond_threshold() {
        // Current 268.2 MiB/s vs baseline 500 → -46%, beyond 10%.
        let baseline = baseline_with(&[("clean-text", 500.0)]);
        let results = check_regression(&clean_samples(), &baseline, 10.0).unwrap();
        assert_eq!(results[1].status, RegStatus::Regressed);
    }

    #[test]
    fn regression_without_baseline_entry_is_informational() {
        let baseline = baseline_with(&[]);
        let results = check_regression(&clean_samples(), &baseline, 10.0).unwrap();
        assert!(results.iter().all(|r| r.status == RegStatus::NoBaseline));
    }

    #[test]
    fn regression_boundary_exactly_at_threshold_fails() {
        // Exactly -10% must count as REGRESSED (the gate is ">N% regression
        // fails"). Numbers chosen so mibs() is exactly 90.0: bytes is
        // 90·2²⁰ and median_ns is 10⁹, so every step is exact in f64, and
        // (90−100)/100·100 rounds to exactly −10.0.
        let bytes = (90.0 * 1024.0 * 1024.0) as u64;
        let current = BenchSample {
            id: "throughput/push/clean-text".to_string(),
            median_ns: 1e9, // 1 s per iteration
            bytes,
        };
        assert_eq!(current.mibs(), 90.0);
        let baseline = baseline_with(&[("clean-text", 100.0)]);
        let results = check_regression(&[current], &baseline, 10.0).unwrap();
        assert_eq!(results[0].change_pct.unwrap(), -10.0);
        assert_eq!(results[0].status, RegStatus::Regressed);
    }

    #[test]
    fn regression_just_inside_threshold_passes() {
        // -9.5% is within the 10% threshold.
        let bytes = (95.0 * 1024.0 * 1024.0) as u64;
        let current = BenchSample {
            id: "throughput/push/clean-text".to_string(),
            median_ns: 1e9,
            bytes,
        };
        let baseline = baseline_with(&[("clean-text", 100.0)]);
        let results = check_regression(&[current], &baseline, 10.0).unwrap();
        assert_eq!(results[0].status, RegStatus::Ok);
    }

    // ── baseline serde ────────────────────────────────────────────────

    #[test]
    fn baseline_parses_committed_format_with_note() {
        let raw = r#"{
  "generated": "2026-09-13",
  "rustc": "rustc 1.98.1",
  "target": "X64",
  "note": "hand-written instructions live here",
  "benchmarks": {"throughput/push/clean-text": {"median_mibs": 268.2}}
}"#;
        let b: Baseline = serde_json::from_str(raw).unwrap();
        assert_eq!(
            b.note.as_deref(),
            Some("hand-written instructions live here")
        );
        assert_eq!(
            b.benchmarks["throughput/push/clean-text"].median_mibs,
            268.2
        );
    }

    #[test]
    fn baseline_missing_median_mibs_is_an_error() {
        let raw = r#"{"benchmarks": {"throughput/push/clean-text": {"wrong_key": 1.0}}}"#;
        assert!(serde_json::from_str::<Baseline>(raw).is_err());
    }

    #[test]
    fn baseline_non_numeric_median_mibs_is_an_error() {
        let raw = r#"{"benchmarks": {"throughput/push/clean-text": {"median_mibs": "fast"}}}"#;
        assert!(serde_json::from_str::<Baseline>(raw).is_err());
    }

    #[test]
    fn baseline_roundtrip() {
        let b = make_baseline(&clean_samples(), "X64", "rustc 1.98.1", "2026-09-13");
        let json = serde_json::to_string_pretty(&b).unwrap();
        let back: Baseline = serde_json::from_str(&json).unwrap();
        assert_eq!(b, back);
        // Deterministic key order (BTreeMap).
        assert!(json.contains("\"throughput/push/clean-json\""));
    }

    #[test]
    fn load_baseline_missing_file_is_none() {
        assert!(
            load_baseline(Path::new("/nonexistent/baseline.json"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn load_baseline_malformed_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        fs::write(&path, "not json").unwrap();
        let err = load_baseline(&path).unwrap_err();
        assert!(err.0.contains("baseline JSON"), "{err}");
    }

    #[test]
    fn make_baseline_structure() {
        let b = make_baseline(&clean_samples(), "ARM64", "rustc 1.98.1", "2026-09-13");
        assert_eq!(b.generated.as_deref(), Some("2026-09-13"));
        assert_eq!(b.rustc.as_deref(), Some("rustc 1.98.1"));
        assert_eq!(b.target.as_deref(), Some("ARM64"));
        assert_eq!(b.benchmarks.len(), 2);
        assert!((b.benchmarks["throughput/push/clean-text"].median_mibs - 268.2).abs() < 0.1);
    }

    // ── date helper ───────────────────────────────────────────────────

    #[test]
    fn civil_from_days_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29)); // leap day
        assert_eq!(civil_from_days(20_709), (2026, 9, 13));
    }

    #[test]
    fn today_iso_is_well_formed() {
        let s = today_iso();
        let bytes = s.as_bytes();
        assert_eq!(bytes.len(), 10);
        assert_eq!(bytes[4], b'-');
        assert_eq!(bytes[7], b'-');
        assert!(s.bytes().all(|b| b.is_ascii_digit() || b == b'-'));
    }
}
