//! Export test vectors as JSON for cross-language parity tests.
//!
//! Reads every vector from `cloak_core::vectors`, computes the expected
//! redacted output with the integration-test key, and prints a JSON array
//! to stdout. Hex encoding for byte fields (lossless, easy for any host
//! language to decode).
//!
//! ```sh
//! cargo run --example export-vectors -p cloak-core \
//!     > adapters/node/test/fixtures/vectors.json
//! ```

use cloak_core::vectors;
use serde_json::{json, Value};

/// Same key material as the parity test suites (`wasm-parity`,
/// `adapters/node`) — changing it breaks all downstream fixtures.
const KEY_MATERIAL: &str = "integration-test-key";

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let key = blake3::derive_key("cloak digest key", KEY_MATERIAL.as_bytes());

    let entries: Vec<Value> = vectors::all_vectors()
        .iter()
        .map(|v| {
            let expected = vectors::expected_output(v, &key);
            json!({
                "name": v.name,
                "input": to_hex(v.input),
                "expected": to_hex(&expected),
            })
        })
        .collect();

    println!(
        "{}",
        serde_json::to_string_pretty(&entries).expect("JSON serialization")
    );
}
