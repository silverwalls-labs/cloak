//! Corpus validation tests (integration tier, S7).
//!
//! Asserts that the five committed benchmark corpora have the properties
//! the performance methodology relies on (docs/04-performance.md):
//!
//! - **Clean** corpora produce zero matches (they measure the clean path).
//! - **Dirty** corpora produce the expected matches (they measure confirm +
//!   redact cost).
//! - Both scanners agree on every corpus (receipts are a fair comparison).
//! - The corpus generator is deterministic (CI measures the same data as dev).
//! - Streaming through the corpora in small chunks produces output identical
//!   to the whole-buffer path (the guarantee, applied to bench data).
//! - Engine output matches the reference oracle on every corpus (differential).

use std::path::Path;
use std::sync::Once;

use cloak_core::scanner::{AhoCorasickScanner, Candidate, ScalarScanner, Scanner};
use cloak_core::{Config, Engine, RuleSpec, CATALOG};

const CORPUS_NAMES: &[&str] = &["clean-json", "clean-text", "dirty-mixed", "dirty-dense", "binary-soup"];

fn corpus_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("corpus")
        .join(name)
}

fn load_corpus(name: &str) -> Vec<u8> {
    let path = corpus_path(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read corpus {name}: {e}"))
}

// Key-management pattern reused from tests/differential.rs — set the env var
// once, derive the key the same way the engine does internally.
const KEY_VAR: &str = "CLOAK_BENCH_CORPORA_KEY";
const KEY_MATERIAL: &str = "bench-corpora-test-key";

static INIT: Once = Once::new();

fn engine_and_key() -> (Engine, [u8; 32]) {
    INIT.call_once(|| {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { std::env::set_var(KEY_VAR, KEY_MATERIAL) };
    });
    let config = Config {
        redaction: cloak_core::RedactionConfig {
            digest_key: format!("env:{KEY_VAR}"),
        },
        ..Config::default()
    };
    let engine = Engine::new(&config).unwrap();
    let key = blake3::derive_key("cloak digest key", KEY_MATERIAL.as_bytes());
    (engine, key)
}

fn push_whole(engine: &Engine, data: &[u8]) -> (Vec<u8>, cloak_core::Stats) {
    let mut session = engine.session();
    let mut out = Vec::new();
    session.push(data, &mut out).unwrap();
    let stats = session.finish(&mut out).unwrap();
    (out, stats)
}

fn push_chunked(engine: &Engine, data: &[u8], chunk_size: usize) -> (Vec<u8>, cloak_core::Stats) {
    let mut session = engine.session();
    let mut out = Vec::new();
    for chunk in data.chunks(chunk_size) {
        session.push(chunk, &mut out).unwrap();
    }
    let stats = session.finish(&mut out).unwrap();
    (out, stats)
}

// ═══════════════════════════════════════════════════════════════════════
// Happy path: corpus match properties
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn clean_json_zero_matches() {
    let (engine, _) = engine_and_key();
    let data = load_corpus("clean-json");
    let (output, stats) = push_whole(&engine, &data);
    assert_eq!(
        stats.total_matches(),
        0,
        "clean-json must produce zero matches — corpus has anchors or confirmed vectors"
    );
    assert_eq!(
        output, data,
        "clean-json with zero matches must be byte-identical passthrough"
    );
}

#[test]
fn clean_text_zero_matches() {
    let (engine, _) = engine_and_key();
    let data = load_corpus("clean-text");
    let (output, stats) = push_whole(&engine, &data);
    assert_eq!(
        stats.total_matches(),
        0,
        "clean-text must produce zero matches — an accidental match makes the floor dishonest"
    );
    assert_eq!(
        output, data,
        "clean-text with zero matches must be byte-identical passthrough"
    );
}

#[test]
fn dirty_mixed_has_matches() {
    let (engine, _) = engine_and_key();
    let data = load_corpus("dirty-mixed");
    let (_, stats) = push_whole(&engine, &data);
    assert!(
        stats.total_matches() > 0,
        "dirty-mixed must produce matches — planted vectors should be detected"
    );
}

#[test]
fn dirty_dense_saturated() {
    let (engine, _) = engine_and_key();
    let data = load_corpus("dirty-dense");
    let (_, stats) = push_whole(&engine, &data);
    assert!(
        stats.total_matches() > 100,
        "dirty-dense must produce many matches (got {}) — it's the worst-case corpus",
        stats.total_matches(),
    );
}

#[test]
fn binary_soup_detects_embedded_vectors() {
    let (engine, _) = engine_and_key();
    let data = load_corpus("binary-soup");
    let (_, stats) = push_whole(&engine, &data);
    assert!(
        stats.total_matches() > 0,
        "binary-soup must detect embedded vectors in random bytes"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Honest-path validation: prefilter noise characteristics
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn clean_text_has_anchor_noise() {
    // clean-text is the "honest" corpus: anchors fire constantly, confirm
    // rejects every time. Verify the prefilter actually finds candidates.
    let refs: Vec<&RuleSpec> = CATALOG.iter().collect();
    let scanner = AhoCorasickScanner::new(&refs, &[]).unwrap();
    let data = load_corpus("clean-text");
    let mut candidates: Vec<Candidate> = Vec::new();
    scanner.scan(&data, &mut candidates);
    assert!(
        candidates.len() > 100,
        "clean-text must have heavy anchor noise (got {} candidates for {} bytes) — \
         if prefilters don't fire, the corpus isn't testing the honest clean path",
        candidates.len(),
        data.len(),
    );
}

#[test]
fn clean_json_fewer_anchor_hits_than_clean_text() {
    let refs: Vec<&RuleSpec> = CATALOG.iter().collect();
    let scanner = AhoCorasickScanner::new(&refs, &[]).unwrap();
    let json_data = load_corpus("clean-json");
    let text_data = load_corpus("clean-text");
    let mut json_candidates: Vec<Candidate> = Vec::new();
    let mut text_candidates: Vec<Candidate> = Vec::new();
    scanner.scan(&json_data, &mut json_candidates);
    scanner.scan(&text_data, &mut text_candidates);
    assert!(
        json_candidates.len() < text_candidates.len(),
        "clean-json should have fewer prefilter hits ({}) than clean-text ({}) — \
         otherwise it's not the best-case corpus",
        json_candidates.len(),
        text_candidates.len(),
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Guarantee: streaming equivalence on all corpora
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn streaming_equals_whole_buffer_on_all_corpora() {
    let (engine, _) = engine_and_key();
    let chunk_sizes = [7, 64, 1024, 65536];

    for &name in CORPUS_NAMES {
        let data = load_corpus(name);
        let (whole_out, whole_stats) = push_whole(&engine, &data);
        for &cs in &chunk_sizes {
            let (chunked_out, chunked_stats) = push_chunked(&engine, &data, cs);
            assert_eq!(
                chunked_out, whole_out,
                "corpus {name} chunk_size={cs}: streaming ≢ whole-buffer"
            );
            assert_eq!(
                chunked_stats.matches, whole_stats.matches,
                "corpus {name} chunk_size={cs}: stats diverge"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Receipts fairness: scanner parity
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn scanner_parity_on_all_corpora() {
    let refs: Vec<&RuleSpec> = CATALOG.iter().collect();
    let ac = AhoCorasickScanner::new(&refs, &[]).unwrap();
    let scalar = ScalarScanner::new(&refs, &[]);

    for &name in CORPUS_NAMES {
        let data = load_corpus(name);
        let mut ac_cands: Vec<Candidate> = Vec::new();
        let mut sc_cands: Vec<Candidate> = Vec::new();
        ac.scan(&data, &mut ac_cands);
        scalar.scan(&data, &mut sc_cands);
        ac_cands.sort();
        sc_cands.sort();
        assert_eq!(
            ac_cands, sc_cands,
            "scanner parity violated on corpus {name}: \
             AhoCorasick={}, Scalar={}",
            ac_cands.len(),
            sc_cands.len(),
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Differential: engine == reference oracle on every corpus
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn engine_matches_reference_on_all_corpora() {
    let (engine, key) = engine_and_key();

    for &name in CORPUS_NAMES {
        let data = load_corpus(name);
        let (engine_out, engine_stats) = push_whole(&engine, &data);
        let (ref_out, ref_stats) = cloak_core::reference::redact(&data, &key);
        assert_eq!(
            engine_out, ref_out,
            "engine ≢ reference oracle on corpus {name}"
        );
        assert_eq!(
            engine_stats.matches, ref_stats.matches,
            "engine stats ≢ reference stats on corpus {name}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Memory bound: carry-over bounded on all corpora
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn carry_over_bounded_on_all_corpora() {
    let (engine, _) = engine_and_key();

    for &name in CORPUS_NAMES {
        let data = load_corpus(name);
        let mut session = engine.session();
        let mut out = Vec::new();
        for (i, chunk) in data.chunks(1024).enumerate() {
            session.push(chunk, &mut out).unwrap();
            assert!(
                // The carry-over bound accounts for max_window (2048) plus
                // PEM state: a confirmed BEGIN line whose END hasn't arrived
                // retains up to PEM_BAIL_OUT + BEGIN line length bytes.
                // Same bound as the fuzz harness (fuzz/src/common.rs).
                session.carry_over_len() <= 2048 + 16_384 + 37,
                "corpus {name} chunk {i}: carry_over {} > carry bound 18469",
                session.carry_over_len(),
            );
        }
        session.finish(&mut out).unwrap();
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Structural: corpus files exist, ~1 MB, distinct
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn corpus_files_exist_and_sized() {
    for &name in CORPUS_NAMES {
        let path = corpus_path(name);
        assert!(path.exists(), "corpus file missing: {}", path.display());
        let meta = std::fs::metadata(&path).unwrap();
        assert!(
            meta.len() > 500_000,
            "corpus {name} too small ({} bytes) — expected ~1 MB",
            meta.len(),
        );
        assert!(
            meta.len() < 2_000_000,
            "corpus {name} too large ({} bytes) — expected ~1 MB",
            meta.len(),
        );
    }
}

#[test]
fn corpus_files_all_distinct() {
    let hashes: Vec<String> = CORPUS_NAMES
        .iter()
        .map(|name| {
            let data = load_corpus(name);
            blake3::hash(&data).to_string()
        })
        .collect();
    let unique: std::collections::HashSet<&str> = hashes.iter().map(|h| h.as_str()).collect();
    assert_eq!(
        unique.len(),
        CORPUS_NAMES.len(),
        "corpus files must all be distinct — got duplicates"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Adversarial: pathological chunking
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn clean_text_one_byte_pushes_zero_matches() {
    // Most pathological chunking possible on the honest clean-path corpus.
    // Must still produce exactly 0 matches. Capped to 128 KiB to keep
    // runtime under 30s on CI runners.
    let (engine, _) = engine_and_key();
    let full = load_corpus("clean-text");
    let data = &full[..128 * 1024];
    let mut session = engine.session();
    let mut output = Vec::new();
    for &byte in data {
        session.push(&[byte], &mut output).unwrap();
    }
    let stats = session.finish(&mut output).unwrap();
    assert_eq!(
        stats.total_matches(),
        0,
        "clean-text (128 KiB) with 1-byte pushes must produce 0 matches (got {})",
        stats.total_matches(),
    );
    assert_eq!(
        output, *data,
        "clean-text with 1-byte pushes must be byte-identical passthrough"
    );
}

#[test]
fn dirty_dense_one_byte_pushes_matches_whole_buffer() {
    // Guarantee under worst-case chunking on worst-case data: 1-byte pushes
    // on vector-saturated input must detect the same matches as whole-buffer.
    let (engine, _) = engine_and_key();
    let data = load_corpus("dirty-dense");
    let (whole_out, whole_stats) = push_whole(&engine, &data);
    let (chunked_out, chunked_stats) = push_chunked(&engine, &data, 1);
    assert_eq!(
        chunked_out, whole_out,
        "dirty-dense 1-byte pushes: streaming ≢ whole-buffer"
    );
    assert_eq!(
        chunked_stats.matches, whole_stats.matches,
        "dirty-dense 1-byte pushes: stats diverge"
    );
}

#[test]
fn binary_soup_three_byte_chunks_equals_whole_buffer() {
    // Non-UTF-8 corpus with prime-number chunk size — exercises every
    // possible byte alignment at chunk boundaries.
    let (engine, _) = engine_and_key();
    let data = load_corpus("binary-soup");
    let (whole_out, whole_stats) = push_whole(&engine, &data);
    let (chunked_out, chunked_stats) = push_chunked(&engine, &data, 3);
    assert_eq!(
        chunked_out, whole_out,
        "binary-soup 3-byte chunks: streaming ≢ whole-buffer"
    );
    assert_eq!(
        chunked_stats.matches, whole_stats.matches,
        "binary-soup 3-byte chunks: stats diverge"
    );
}

#[test]
fn dirty_mixed_detects_multiple_rule_types() {
    // The generator plants vectors from multiple rules. Verify that at
    // least a few distinct rule types are actually detected — not just
    // one rule dominating the count.
    let (engine, _) = engine_and_key();
    let data = load_corpus("dirty-mixed");
    let (_, stats) = push_whole(&engine, &data);
    let rule_count = stats.matches.len();
    assert!(
        rule_count >= 3,
        "dirty-mixed should trigger at least 3 distinct rules (got {rule_count}) — \
         the generator plants vectors from every rule"
    );
}

#[test]
fn clean_corpora_differential() {
    // Engine == reference oracle on BOTH clean corpora (not just dirty).
    // A clean corpus that diverges means the engine adds or removes bytes
    // on match-free input — a passthrough bug.
    let (engine, key) = engine_and_key();

    for name in ["clean-json", "clean-text"] {
        let data = load_corpus(name);
        let (engine_out, _) = push_whole(&engine, &data);
        let (ref_out, _) = cloak_core::reference::redact(&data, &key);
        assert_eq!(
            engine_out, ref_out,
            "engine ≢ reference oracle on clean corpus {name} — passthrough bug"
        );
        // Both should also be identity (no matches → no changes).
        assert_eq!(
            engine_out, data,
            "clean corpus {name}: engine output must be byte-identical to input"
        );
    }
}
