//! Corpus generation logic for the five committed benchmark corpora
//! (docs/04-performance.md). Shared between the `gen_bench_corpora`
//! example (writer) and `tests/corpus_determinism.rs` (pin) so the
//! committed files cannot drift from the generator.
//!
//! Deterministic: seeded RNG (`rand::rngs::StdRng`) — same seed, same
//! bytes. Avoid iteration-order-dependent collections here.

use std::fmt::Write as _;

use rand::Rng;
use rand::rngs::StdRng;

use cloak_core::vectors;

pub const TARGET_SIZE: usize = 1_024 * 1_024; // ~1 MB per corpus

/// One corpus: stable name, generator, RNG seed. Shared by the writer
/// example and the determinism pin test — the seeds are part of the
/// committed-corpora contract.
pub fn corpora() -> Vec<(&'static str, CorpusGen, u64)> {
    vec![
        ("clean-json", gen_clean_json, 1),
        ("clean-text", gen_clean_text, 2),
        ("dirty-mixed", gen_dirty_mixed, 3),
        ("dirty-dense", gen_dirty_dense, 4),
        ("binary-soup", gen_binary_soup, 5),
    ]
}

pub type CorpusGen = fn(&mut StdRng) -> Vec<u8>;

// ---------------------------------------------------------------------------
// clean-json: synthetic JSON logs, zero anchors, zero matches
// ---------------------------------------------------------------------------

fn gen_clean_json(rng: &mut StdRng) -> Vec<u8> {
    let mut buf = String::with_capacity(TARGET_SIZE + 4096);
    let levels = ["INFO", "DEBUG", "WARN", "TRACE"];
    let services = [
        "api-gateway",
        "auth-svc",
        "order-svc",
        "payment-svc",
        "inventory",
    ];
    let messages = [
        "request completed",
        "cache hit",
        "cache miss",
        "connection established",
        "health check passed",
        "batch processed",
        "retry succeeded",
        "config reloaded",
        "task scheduled",
        "snapshot created",
    ];

    let mut line_no: u64 = 0;
    while buf.len() < TARGET_SIZE {
        let level = levels[rng.random_range(0..levels.len())];
        let svc = services[rng.random_range(0..services.len())];
        let msg = messages[rng.random_range(0..messages.len())];
        // Duration values capped at 999 to avoid multi-digit runs that
        // could form credit-card-length sequences when adjacent to other
        // numeric JSON fields (e.g., "duration_ms":4523,"...":1234 → the
        // run 45231234 could match a CC anchor).
        let dur = rng.random_range(1u32..999);
        // Trace/span IDs: hex with forced 'a' nibbles every 4 chars to
        // prevent digit-only runs that could form credit-card numbers.
        // CC anchors (34, 37, 4, 51-55, 6011, 65) need 13+ contiguous
        // digits (with optional spaces/dashes); a hex letter every 4 chars
        // limits the longest digit run to 3, well below the 13-digit minimum.
        let trace: u64 = rng.random();
        let span: u32 = rng.random();
        let trace_hex = format!("{trace:016x}");
        let span_hex = format!("{span:08x}");
        let trace_safe = force_hex_letters(&trace_hex);
        let span_safe = force_hex_letters(&span_hex);
        write!(
            buf,
            r#"{{"ts":"2026-09-06T12:{:02}:{:02}Z","level":"{level}","service":"{svc}","msg":"{msg}","duration_ms":{dur},"trace_id":"{trace_safe}","span_id":"{span_safe}","line":{line_no}}}"#,
            rng.random_range(0u8..60),
            rng.random_range(0u8..60),
        )
        .unwrap();
        buf.push('\n');
        line_no += 1;
    }
    buf.into_bytes()
}

// ---------------------------------------------------------------------------
// clean-text: app logs with heavy anchor noise, zero matches
// ---------------------------------------------------------------------------

fn gen_clean_text(rng: &mut StdRng) -> Vec<u8> {
    let mut buf = String::with_capacity(TARGET_SIZE + 4096);

    // Templates with anchor noise that will fire prefilters but fail confirm:
    //   @  — fires email anchor, but "user@" without domain fails confirm
    //   :// — fires connection-string anchor, but "http://" is not a DB scheme
    //   digit-dot — fires ipv4 anchor, but "1.2.3" is only 3 octets
    //   +  — fires phone anchor, but "+abc" has no digits
    //   eyJ — fires JWT anchor, but "eyJunk" has no dots
    //   AKIA — fires AWS anchor, but "AKIAnope" is only 8 chars
    //   ghp_ — fires GitHub anchor, but "ghp_short" is < 36 chars
    let templates = [
        "request from 1.2.3 via http://proxy status=200",
        "notify @admin: metric +5 delta version=3.14.1",
        "trace eyJunk.data stream://internal latency=0.5",
        "user@: connected to http://localhost test+case",
        "build v2.8.0 ghp_short npm_abc offset=1.0.0",
        "host 10.0 route=http://cdn ref=1.2 pool+size=8",
        "deploy @ci target://staging delta +ok 9.8.7",
        "AKIAnope config: debug://local ver=4.5.6",
        "cache @miss https://docs ratio=0.97 op+count",
        "log 1.0 via ws://hub key=ghp_ metric +0",
    ];

    let mut line_no: u64 = 0;
    while buf.len() < TARGET_SIZE {
        let tmpl = templates[rng.random_range(0..templates.len())];
        let ts_h = rng.random_range(0u8..24);
        let ts_m = rng.random_range(0u8..60);
        let ts_s = rng.random_range(0u8..60);
        writeln!(
            buf,
            "2026-09-06T{ts_h:02}:{ts_m:02}:{ts_s:02}Z INFO [app-{:02}] {tmpl} seq={line_no}",
            rng.random_range(0u8..10),
        )
        .unwrap();
        line_no += 1;
    }
    buf.into_bytes()
}

// ---------------------------------------------------------------------------
// dirty-mixed: clean base + planted vectors every 500 lines
// ---------------------------------------------------------------------------

fn gen_dirty_mixed(rng: &mut StdRng) -> Vec<u8> {
    // Uses Vec<u8> directly (not String) because planted vectors may contain
    // non-UTF-8 bytes. String::from_utf8_lossy would replace invalid bytes
    // with U+FFFD, silently corrupting the vector's byte pattern so the
    // engine can't detect it.
    let mut buf = Vec::with_capacity(TARGET_SIZE + 4096);
    let all_vecs = vectors::all_vectors();
    // Only positive vectors (those that should match).
    let positive: Vec<_> = all_vecs.iter().filter(|v| !v.spans.is_empty()).collect();

    let templates: &[&[u8]] = &[
        b"request completed duration=42",
        b"cache hit ratio=0.98",
        b"health check passed",
        b"batch processed count=100",
        b"config reloaded successfully",
    ];

    // Deliberate deviation from issue #10's "~1/10k lines": at ~1 MB that
    // yields only 1-2 planted vectors — not enough to exercise multiple
    // rules (see `dirty_mixed_detects_multiple_rule_types`). Every 500
    // lines (~1/500, 20× denser than spec) gives a richer confirm/redact
    // workload while staying a small fraction of total lines.
    let mut line_no: u64 = 0;
    let mut vec_idx = 0;
    while buf.len() < TARGET_SIZE {
        // Plant a vector approximately every 500 lines (~50 KB).
        if line_no > 0 && line_no.is_multiple_of(500) && vec_idx < positive.len() {
            let v = positive[vec_idx];
            buf.extend_from_slice(b"2026-09-06T12:00:00Z WARN [planted] ");
            buf.extend_from_slice(v.input);
            buf.push(b'\n');
            vec_idx += 1;
        } else {
            let tmpl = templates[rng.random_range(0..templates.len())];
            buf.extend_from_slice(b"2026-09-06T12:00:00Z INFO [app] ");
            buf.extend_from_slice(tmpl);
            buf.extend_from_slice(format!(" seq={line_no}\n").as_bytes());
        }
        line_no += 1;
    }
    buf
}

// ---------------------------------------------------------------------------
// dirty-dense: vector-saturated input
// ---------------------------------------------------------------------------

fn gen_dirty_dense(_rng: &mut StdRng) -> Vec<u8> {
    let mut buf = Vec::with_capacity(TARGET_SIZE + 4096);
    let all_vecs = vectors::all_vectors();
    let positive: Vec<_> = all_vecs.iter().filter(|v| !v.spans.is_empty()).collect();

    if positive.is_empty() {
        // Fallback: shouldn't happen with the current catalog.
        return vec![b'x'; TARGET_SIZE];
    }

    let separator = b"\n---\n";
    let mut idx = 0;
    while buf.len() < TARGET_SIZE {
        let v = positive[idx % positive.len()];
        buf.extend_from_slice(v.input);
        buf.extend_from_slice(separator);
        idx += 1;
    }
    buf.truncate(TARGET_SIZE);
    buf
}

// ---------------------------------------------------------------------------
// binary-soup: random bytes + embedded vectors
// ---------------------------------------------------------------------------

fn gen_binary_soup(rng: &mut StdRng) -> Vec<u8> {
    let mut buf = Vec::with_capacity(TARGET_SIZE + 4096);
    let all_vecs = vectors::all_vectors();
    let positive: Vec<_> = all_vecs.iter().filter(|v| !v.spans.is_empty()).collect();

    let mut vec_idx = 0;
    while buf.len() < TARGET_SIZE {
        // ~4 KiB of random bytes between each vector.
        let gap: usize = rng.random_range(2048..6144);
        for _ in 0..gap {
            buf.push(rng.random());
        }
        if vec_idx < positive.len() {
            buf.extend_from_slice(positive[vec_idx].input);
            vec_idx += 1;
        }
    }
    buf.truncate(TARGET_SIZE);
    buf
}

/// Replace every 4th hex character with 'a' to ensure no digit-only run
/// exceeds 3 characters. This prevents accidental credit-card matches
/// (which need 13+ digits) while keeping the IDs readable hex.
fn force_hex_letters(hex: &str) -> String {
    hex.char_indices()
        .map(|(i, c)| if i % 4 == 3 { 'a' } else { c })
        .collect()
}
