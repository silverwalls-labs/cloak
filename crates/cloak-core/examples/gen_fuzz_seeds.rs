//! Materializes the committed fuzz seed corpora from the canonical vector
//! suites — vector data is defined once (`src/rules/vectors/`) and reused
//! verbatim per tier (docs/03), so the corpus is generated, never
//! hand-copied.
//!
//! Usage: `cargo run -p cloak-core --example gen_fuzz_seeds`
//! Output lands in `crates/cloak-core/fuzz/corpus/<target>/` and is
//! committed; CI replays it as the fuzz regression gate. Re-run whenever
//! vectors change. Existing files (e.g. committed crash reproducers) are
//! left alone unless a seed of the same name changed.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use cloak_core::vectors;

fn corpus_dir(target: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/corpus")
        .join(target)
}

/// Write one seed, guarding against two distinct vector names sanitizing to
/// the same filename (which would silently drop a seed). `used` tracks
/// sanitized→original within a directory; a collision is a hard error so the
/// vector must be renamed rather than lose corpus coverage.
fn write_seed(dir: &Path, name: &str, bytes: &[u8], used: &mut HashMap<String, String>) {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if let Some(prev) = used.insert(sanitized.clone(), name.to_string()) {
        panic!("seed filename collision: {prev:?} and {name:?} both sanitize to {sanitized:?}");
    }
    fs::write(dir.join(sanitized), bytes).unwrap_or_else(|e| panic!("write seed {name}: {e}"));
}

fn main() {
    // fuzz_engine_stream: every vector, positive and negative.
    let engine_dir = corpus_dir("fuzz_engine_stream");
    fs::create_dir_all(&engine_dir).expect("create corpus dir");
    let all = vectors::all_vectors();
    let mut engine_used = HashMap::new();
    for v in &all {
        write_seed(&engine_dir, v.name, v.input, &mut engine_used);
    }
    println!("fuzz_engine_stream: {} seeds", all.len());

    // fuzz_pem_state: the PEM suites + handcrafted adversarial shapes the
    // vector corpus doesn't contain (state-machine edges, not detections).
    let pem_dir = corpus_dir("fuzz_pem_state");
    fs::create_dir_all(&pem_dir).expect("create corpus dir");
    let pem_vectors: Vec<_> = vectors::pem::POSITIVE
        .iter()
        .chain(vectors::pem::NEGATIVE)
        .collect();
    let mut pem_used = HashMap::new();
    for v in &pem_vectors {
        write_seed(&pem_dir, v.name, v.input, &mut pem_used);
    }
    let adversarial: &[(&str, Vec<u8>)] = &[
        (
            "adv-nested-begin-in-body",
            b"-----BEGIN RSA PRIVATE KEY-----\n-----BEGIN EC PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n"
                .to_vec(),
        ),
        (
            "adv-unterminated-begin",
            b"-----BEGIN OPENSSH PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\nMIIEpAIBAAKCAQEA".to_vec(),
        ),
        ("adv-begin-at-eof", b"log line\n-----BEGIN PRIVATE KEY-----".to_vec()),
        (
            "adv-end-before-begin",
            b"-----END RSA PRIVATE KEY-----\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n"
                .to_vec(),
        ),
        (
            "adv-back-to-back-begins",
            b"-----BEGIN RSA PRIVATE KEY-----\n-----BEGIN RSA PRIVATE KEY-----\n-----BEGIN DSA PRIVATE KEY-----\n"
                .to_vec(),
        ),
        ("adv-bailout-17k-body", {
            // Body crossing PEM_BAIL_OUT (16 KiB): 265 lines x 64 chars.
            let mut input = b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n".to_vec();
            for _ in 0..265 {
                input.extend_from_slice(&[b'A'; 64]);
                input.push(b'\n');
            }
            input.extend_from_slice(b"-----END ENCRYPTED PRIVATE KEY-----\n");
            input
        }),
    ];
    for (name, bytes) in adversarial {
        write_seed(&pem_dir, name, bytes, &mut pem_used);
    }
    println!(
        "fuzz_pem_state: {} seeds",
        pem_vectors.len() + adversarial.len()
    );

    // fuzz_config: TOML shapes from the config unit suite — valid, invalid,
    // and malformed.
    let config_dir = corpus_dir("fuzz_config");
    fs::create_dir_all(&config_dir).expect("create corpus dir");
    let configs: &[(&str, &str)] = &[
        ("toml-empty", ""),
        (
            "toml-full-valid",
            "[redaction]\ndigest_key = \"env:CLOAK_DIGEST_KEY\"\n\n[rules.github-token]\nenabled = true\n\n[rules.phone-intl]\nenabled = false\n",
        ),
        (
            "toml-disable-pem",
            "[rules.pem-private-key]\nenabled = false\n",
        ),
        ("toml-unknown-rule", "[rules.not-a-rule]\nenabled = false\n"),
        ("toml-unknown-field", "[redaction]\nnot_a_field = 1\n"),
        ("toml-bare-env", "[redaction]\ndigest_key = \"env:\"\n"),
        (
            "toml-non-env-key",
            "[redaction]\ndigest_key = \"hunter2\"\n",
        ),
        (
            "toml-type-mismatch",
            "[rules.github-token]\nenabled = \"yes\"\n",
        ),
        ("toml-malformed", "[[[broken"),
    ];
    let mut config_used = HashMap::new();
    for (name, s) in configs {
        write_seed(&config_dir, name, s.as_bytes(), &mut config_used);
    }
    println!("fuzz_config: {} seeds", configs.len());
}
