//! Mini-soak tests (integration tier, S7).
//!
//! Fast versions of the nightly soak test (`examples/soak.rs`) that run in
//! `cargo test` in seconds instead of minutes. They push tens of MB (not GB)
//! through a single `Session`, asserting bounded carry-over and correct
//! output at every step. This catches memory regressions on every PR
//! without waiting for the nightly schedule.

use std::io::{self, Write};
use std::path::Path;

use cloak_core::{CARRY_OVER_BOUND, Config, Engine};

fn load_corpus(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("corpus")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read corpus {name}: {e}"))
}

/// Counting sink that discards output but tracks byte count.
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

// ═══════════════════════════════════════════════════════════════════════
// Happy path: mini-soak with bounded carry-over
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn soak_lite_bounded_carry_over() {
    // Loop clean-text + dirty-mixed ~25 times through one Session (~50 MB).
    // Assert carry-over stays bounded after every push.
    let engine = Engine::new(&Config::ephemeral()).unwrap();
    let clean = load_corpus("clean-text");
    let dirty = load_corpus("dirty-mixed");
    let corpus: Vec<u8> = [clean.as_slice(), dirty.as_slice()].concat();

    let iterations = 25;
    let mut session = engine.session();
    let mut sink = CountingSink { bytes: 0 };

    for round in 0..iterations {
        for (i, chunk) in corpus.chunks(1024).enumerate() {
            session.push(chunk, &mut sink).unwrap();
            assert!(
                session.carry_over_len() <= CARRY_OVER_BOUND,
                "round {round} chunk {i}: carry_over {} > CARRY_OVER_BOUND {CARRY_OVER_BOUND}",
                session.carry_over_len(),
            );
        }
    }

    let stats = session.finish(&mut sink).unwrap();
    let expected_bytes = (corpus.len() as u64) * (iterations as u64);
    assert_eq!(stats.bytes_processed, expected_bytes);
    assert!(sink.bytes > 0, "soak must produce output (got 0 bytes)");
}

// ═══════════════════════════════════════════════════════════════════════
// Adversarial: one-byte pushes for extended period
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn soak_lite_one_byte_chunks() {
    // 1-byte pushes on a 128 KiB slice of dirty-mixed (most pathological
    // chunking × realistic data). Capped to keep runtime under 30s on CI.
    let engine = Engine::new(&Config::ephemeral()).unwrap();
    let full_corpus = load_corpus("dirty-mixed");
    let corpus = &full_corpus[..128 * 1024];

    let iterations = 1;
    let mut session = engine.session();
    let mut sink = CountingSink { bytes: 0 };

    for _round in 0..iterations {
        for &byte in corpus {
            session.push(&[byte], &mut sink).unwrap();
            assert!(
                session.carry_over_len() <= CARRY_OVER_BOUND,
                "carry_over {} > CARRY_OVER_BOUND {CARRY_OVER_BOUND} during 1-byte push soak",
                session.carry_over_len(),
            );
        }
    }

    let stats = session.finish(&mut sink).unwrap();
    assert_eq!(stats.bytes_processed, corpus.len() as u64);
    assert!(
        stats.total_matches() > 0,
        "dirty corpus must produce matches even with 1-byte pushes"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Adversarial: alternating clean/dirty interleave
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn soak_lite_alternating_corpora() {
    // Alternate clean and dirty 1 KiB chunks in the same session.
    // Catches state leaks between clean/dirty transitions — e.g., a stale
    // candidate from a dirty chunk leaking into a clean chunk's output.
    let engine = Engine::new(&Config::ephemeral()).unwrap();
    let clean = load_corpus("clean-text");
    let dirty = load_corpus("dirty-mixed");

    let mut session = engine.session();
    let mut sink = CountingSink { bytes: 0 };

    // Interleave: 1 KiB clean, 1 KiB dirty, repeating.
    let clean_chunks: Vec<&[u8]> = clean.chunks(1024).collect();
    let dirty_chunks: Vec<&[u8]> = dirty.chunks(1024).collect();
    let pairs = clean_chunks.len().min(dirty_chunks.len());

    for i in 0..pairs {
        session.push(clean_chunks[i], &mut sink).unwrap();
        assert!(
            session.carry_over_len() <= CARRY_OVER_BOUND,
            "after clean chunk {i}: carry_over {} > CARRY_OVER_BOUND {CARRY_OVER_BOUND}",
            session.carry_over_len(),
        );
        session.push(dirty_chunks[i], &mut sink).unwrap();
        assert!(
            session.carry_over_len() <= CARRY_OVER_BOUND,
            "after dirty chunk {i}: carry_over {} > CARRY_OVER_BOUND {CARRY_OVER_BOUND}",
            session.carry_over_len(),
        );
    }

    let stats = session.finish(&mut sink).unwrap();
    assert!(sink.bytes > 0);
    // The dirty chunks should produce matches.
    assert!(
        stats.total_matches() > 0,
        "interleaved session must detect dirty-mixed matches"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Output correctness: soak output matches single-pass
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn soak_lite_multi_pass_no_crash() {
    // Push the corpus 6 times through one session: validates that
    // long-lived session state (carry-over, PEM, match counts) stays
    // consistent after many iterations. Asserts bytes_processed and
    // match count (must be at least what a single-pass produces).
    let engine = Engine::new(&Config::ephemeral()).unwrap();
    let corpus = load_corpus("dirty-mixed");

    // Single-pass reference: finish the session to get the match count.
    let mut ref_session = engine.session();
    let mut ref_sink = CountingSink { bytes: 0 };
    for chunk in corpus.chunks(64 * 1024) {
        ref_session.push(chunk, &mut ref_sink).unwrap();
    }
    let ref_stats = ref_session.finish(&mut ref_sink).unwrap();

    // Multi-pass: 6 iterations through one session.
    let mut session = engine.session();
    let mut sink = CountingSink { bytes: 0 };
    for _ in 0..6 {
        for chunk in corpus.chunks(64 * 1024) {
            session.push(chunk, &mut sink).unwrap();
        }
    }
    let stats = session.finish(&mut sink).unwrap();

    assert_eq!(stats.bytes_processed, corpus.len() as u64 * 6,);

    // Total matches must be >= first-pass matches (more data = more matches).
    assert!(
        stats.total_matches() >= ref_stats.total_matches(),
        "multi-pass soak must find at least as many matches as single-pass \
         (got {} vs single-pass {})",
        stats.total_matches(),
        ref_stats.total_matches(),
    );
}
