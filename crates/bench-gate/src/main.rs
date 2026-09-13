//! CLI for the bench gate. Exit codes: 0 pass, 1 gate failure or error,
//! 2 usage. Kept thin — all logic lives in the lib (covered by the unit
//! tier and the coverage gates).

use std::path::PathBuf;
use std::process::ExitCode;

use bench_gate::{
    Baseline, GateError, RegStatus, check_floor, check_regression, discover, load_baseline,
    make_baseline, today_iso,
};

const USAGE: &str = "\
CI gate for criterion benchmark results (reads target/criterion directly).

Usage: bench-gate <command> [options]

Commands:
  floor           Check the worse clean-corpus throughput against a floor.
                  --criterion <dir>    criterion output dir (default: target/criterion)
                  --floor-mbs <n>      floor in MB/s (required)

  regression      Check every benchmark against a stored baseline.
                  --criterion <dir>    criterion output dir (default: target/criterion)
                  --baseline <file>    baseline JSON (required; missing file = warn + pass)
                  --threshold-pct <n>  regression threshold in % (required)

  emit-baseline   Write a baseline JSON from the current criterion results.
                  --criterion <dir>    criterion output dir (default: target/criterion)
                  --out <file>         output path (required)
                  --target <str>      target metadata (e.g. X64, ARM64)
";

fn main() -> ExitCode {
    // nosemgrep: rust.lang.security.args.args — CI tool reading its own
    // flags; argv is not used for any security decision (no privilege
    // boundary, no secret handling).
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("ERROR: {e}");
            ExitCode::from(1)
        }
    }
}

/// Value of `--<name>` in the remaining args, if present.
fn flag_value(args: &[String], name: &str) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == name {
            return it.next().cloned();
        }
    }
    None
}

fn required_flag(args: &[String], name: &str) -> Result<String, GateError> {
    flag_value(args, name)
        .ok_or_else(|| GateError(format!("missing required flag {name}\n\n{USAGE}")))
}

fn criterion_dir(args: &[String]) -> Result<PathBuf, GateError> {
    Ok(PathBuf::from(
        flag_value(args, "--criterion").unwrap_or_else(|| "target/criterion".to_string()),
    ))
}

fn parse_number(raw: &str, flag: &str) -> Result<f64, GateError> {
    raw.parse()
        .map_err(|_| GateError(format!("invalid value for {flag}: {raw:?}")))
}

fn run(args: &[String]) -> Result<ExitCode, GateError> {
    let Some(command) = args.first() else {
        eprint!("{USAGE}");
        return Ok(ExitCode::from(2));
    };
    let rest = &args[1..];

    match command.as_str() {
        "floor" => run_floor(rest),
        "regression" => run_regression(rest),
        "emit-baseline" => run_emit_baseline(rest),
        _ => {
            eprint!("{USAGE}");
            Ok(ExitCode::from(2))
        }
    }
}

fn run_floor(args: &[String]) -> Result<ExitCode, GateError> {
    let floor_mbs = parse_number(&required_flag(args, "--floor-mbs")?, "--floor-mbs")?;
    let samples = discover(&criterion_dir(args)?)?;
    let outcome = check_floor(&samples, floor_mbs)?;

    println!("clean-json: {:.1} MB/s", outcome.clean_json_mbs);
    println!("clean-text: {:.1} MB/s", outcome.clean_text_mbs);
    println!(
        "floor reference (worse): {:.1} MB/s (gate: >= {floor_mbs} MB/s)",
        outcome.worse_mbs
    );
    if outcome.passed {
        println!(
            "PASS: {:.1} MB/s >= {floor_mbs} MB/s floor",
            outcome.worse_mbs
        );
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!(
            "FAIL: {:.1} MB/s < {floor_mbs} MB/s floor",
            outcome.worse_mbs
        );
        Ok(ExitCode::from(1))
    }
}

fn run_regression(args: &[String]) -> Result<ExitCode, GateError> {
    let baseline_path = PathBuf::from(required_flag(args, "--baseline")?);
    let threshold_pct = parse_number(&required_flag(args, "--threshold-pct")?, "--threshold-pct")?;

    let Some(baseline) = load_baseline(&baseline_path)? else {
        println!(
            "WARNING: baseline file {} not found — skipping regression check",
            baseline_path.display()
        );
        println!("Run the benches and commit a baseline to enable regression gating.");
        return Ok(ExitCode::SUCCESS);
    };

    let samples = discover(&criterion_dir(args)?)?;
    let results = check_regression(&samples, &baseline, threshold_pct)?;

    let mut regressions = 0;
    for r in &results {
        match r.status {
            RegStatus::NoBaseline => {
                println!(
                    "  {}: {:.1} MiB/s (no baseline — skipped)",
                    r.id, r.current_mibs
                )
            }
            RegStatus::Ok => println!(
                "  {}: {:.1} MiB/s (baseline: {:.1}, {:+.1}%) [OK]",
                r.id,
                r.current_mibs,
                r.baseline_mibs.unwrap(),
                r.change_pct.unwrap()
            ),
            RegStatus::Regressed => {
                regressions += 1;
                println!(
                    "  {}: {:.1} MiB/s (baseline: {:.1}, {:+.1}%) [REGRESSED]",
                    r.id,
                    r.current_mibs,
                    r.baseline_mibs.unwrap(),
                    r.change_pct.unwrap()
                );
            }
        }
    }

    if regressions > 0 {
        eprintln!("FAIL: {regressions} benchmark(s) regressed beyond {threshold_pct}%");
        Ok(ExitCode::from(1))
    } else {
        println!("PASS: no regressions beyond {threshold_pct}%");
        Ok(ExitCode::SUCCESS)
    }
}

fn run_emit_baseline(args: &[String]) -> Result<ExitCode, GateError> {
    let out_path = PathBuf::from(required_flag(args, "--out")?);
    let target = flag_value(args, "--target").unwrap_or_default();
    let samples = discover(&criterion_dir(args)?)?;

    let baseline: Baseline = make_baseline(&samples, &target, &rustc_version(), &today_iso());
    let json = serde_json::to_string_pretty(&baseline)
        .map_err(|e| GateError(format!("serialize baseline: {e}")))?;
    std::fs::write(&out_path, json + "\n")
        .map_err(|e| GateError(format!("write {}: {e}", out_path.display())))?;

    println!("wrote {}:", out_path.display());
    for (id, entry) in &baseline.benchmarks {
        println!("  {id}: {:.1} MiB/s", entry.median_mibs);
    }
    Ok(ExitCode::SUCCESS)
}

/// Best-effort `rustc --version` for baseline metadata.
fn rustc_version() -> String {
    std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}
