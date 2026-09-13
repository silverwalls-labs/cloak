//! Soak test: push tens of GB through a single `Session`, assert flat RSS.
//!
//! Proves bounded memory as an *observed fact* — the proptest invariant
//! (docs/03-guarantee-and-testing.md), made empirical.
//!
//! Usage: `cargo run -p cloak-core --example soak --release`
//!
//! Environment variables (all optional):
//!   SOAK_TARGET_GB   — total data to push (default: 10)
//!   SOAK_RSS_LIMIT_MB — maximum allowed RSS (default: 100)
//!   SOAK_CHECK_INTERVAL_MB — how often to sample RSS (default: 512)

use std::io::{self, Write};
use std::path::Path;
use std::time::Instant;

use cloak_core::{Config, Engine};

const CHUNK_SIZE: usize = 64 * 1024;

fn load_corpus(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("corpus")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read corpus {}: {e}", path.display()))
}

/// Output sink that counts bytes without accumulating them.
struct CountingSink {
    bytes: u64,
}

impl Write for CountingSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Read `VmRSS` from `/proc/self/status` (Linux only).
#[cfg(target_os = "linux")]
fn get_rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let num_str = rest.trim().strip_suffix("kB")?.trim();
            return num_str.parse().ok();
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn get_rss_kb() -> Option<u64> {
    None // RSS measurement not available on this platform
}

/// Unset → default; present but unparseable → panic. This is a CI harness:
/// a typo'd `SOAK_TARGET_GB=1O` must fail loudly, not silently run defaults.
fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    match std::env::var(key) {
        Ok(s) => s
            .parse()
            .unwrap_or_else(|_| panic!("soak: invalid {key}={s:?}")),
        Err(_) => default,
    }
}

fn main() {
    let target_gb: u64 = env_or("SOAK_TARGET_GB", 10);
    let rss_limit_mb: u64 = env_or("SOAK_RSS_LIMIT_MB", 100);
    let check_interval_mb: u64 = env_or("SOAK_CHECK_INTERVAL_MB", 512);

    let target_bytes = target_gb * 1024 * 1024 * 1024;
    let check_interval_bytes = check_interval_mb * 1024 * 1024;

    eprintln!(
        "soak: target={target_gb} GB, rss_limit={rss_limit_mb} MB, check_interval={check_interval_mb} MB"
    );

    // Load corpora — concat clean-text + dirty-mixed for a realistic mix.
    let clean = load_corpus("clean-text");
    let dirty = load_corpus("dirty-mixed");
    let corpus: Vec<u8> = [clean.as_slice(), dirty.as_slice()].concat();
    eprintln!(
        "soak: corpus size = {} bytes ({} MB looped)",
        corpus.len(),
        corpus.len() / (1024 * 1024)
    );

    let engine = Engine::new(&Config::ephemeral()).unwrap();
    let mut session = engine.session();
    let mut sink = CountingSink { bytes: 0 };

    let mut total_bytes: u64 = 0;
    let mut next_check = check_interval_bytes;
    let mut min_rss_kb: u64 = u64::MAX;
    let mut max_rss_kb: u64 = 0;
    let mut rss_available = false;

    // Initial RSS sample.
    if let Some(rss) = get_rss_kb() {
        min_rss_kb = rss;
        max_rss_kb = rss;
        rss_available = true;
        eprintln!("soak: initial RSS = {rss} KB ({} MB)", rss / 1024);
    } else {
        eprintln!("soak: RSS measurement not available on this platform — skipping RSS assertion");
    }

    let start = Instant::now();

    while total_bytes < target_bytes {
        for chunk in corpus.chunks(CHUNK_SIZE) {
            session.push(chunk, &mut sink).unwrap();
            total_bytes += chunk.len() as u64;

            if total_bytes >= next_check {
                if let Some(rss) = get_rss_kb() {
                    min_rss_kb = min_rss_kb.min(rss);
                    max_rss_kb = max_rss_kb.max(rss);
                    let elapsed = start.elapsed().as_secs_f64();
                    let throughput_mbs = total_bytes as f64 / (1024.0 * 1024.0) / elapsed;
                    eprintln!(
                        "soak: {:.1} GB processed, RSS = {} KB ({} MB), throughput = {:.0} MB/s",
                        total_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
                        rss,
                        rss / 1024,
                        throughput_mbs,
                    );

                    assert!(
                        rss < rss_limit_mb * 1024,
                        "RSS exceeded limit: {} MB > {} MB",
                        rss / 1024,
                        rss_limit_mb,
                    );
                }
                next_check += check_interval_bytes;
            }
        }
    }

    // Finish the session.
    let stats = session.finish(&mut sink).unwrap();
    let elapsed = start.elapsed();
    let throughput_mbs = total_bytes as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64();

    // Final RSS sample.
    if let Some(rss) = get_rss_kb() {
        min_rss_kb = min_rss_kb.min(rss);
        max_rss_kb = max_rss_kb.max(rss);
    }

    // Assert RSS delta BEFORE printing PASSED — a panic after "PASSED"
    // is confusing in CI logs.
    if rss_available {
        let delta_mb = max_rss_kb.saturating_sub(min_rss_kb) / 1024;
        // The delta should be small — a few MB at most. The engine's memory
        // is O(W) bounded; any growth is allocator jitter or initial warmup.
        assert!(
            delta_mb < 50,
            "RSS delta too large: {} MB — possible memory leak",
            delta_mb,
        );
    }

    eprintln!();
    eprintln!("soak: PASSED");
    eprintln!(
        "  total:      {:.1} GB",
        total_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    );
    eprintln!("  elapsed:    {:.1} s", elapsed.as_secs_f64());
    eprintln!("  throughput: {throughput_mbs:.0} MB/s");
    eprintln!(
        "  output:     {:.1} GB",
        sink.bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    );
    eprintln!("  matches:    {}", stats.total_matches());
    if rss_available {
        eprintln!(
            "  RSS range:  {} – {} KB (delta = {} KB)",
            min_rss_kb,
            max_rss_kb,
            max_rss_kb.saturating_sub(min_rss_kb)
        );
    }
}
