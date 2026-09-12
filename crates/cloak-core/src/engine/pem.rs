//! Stateful PEM private-key detector (docs/02-rules.md, `pem-private-key`).
//!
//! PEM blocks are multi-line and can span many chunks, so they don't fit the
//! windowed prefilter→confirm→overlap pipeline used by single-line rules.
//! Instead, this module implements a small state machine layered alongside
//! the regular matching engine:
//!
//! - The `-----BEGIN ` anchor is included in the shared prefilter.
//! - Blocks whose BEGIN and END both lie in the current buffer are redacted
//!   by the regular pipeline (body span → overlap merge), exactly matching
//!   the reference oracle.
//! - On a confirmed private-key BEGIN whose END has not arrived yet, the
//!   engine emits the BEGIN line, enters [`PemState::InBlock`], and hashes
//!   the body incrementally as further pushes arrive.
//! - On END (or bail-out / finish) a single `[CLOAK:pem-private-key:<digest>]`
//!   tag replaces the body. The BEGIN and END markers stay visible in output.
//! - Bail-out: at most `PEM_BAIL_OUT` body bytes are redacted. The digest
//!   covers exactly `PEM_BAIL_OUT` bytes (identical to the whole-buffer
//!   path), and everything past the truncation point goes back through
//!   normal scanning — regular rules and nested BEGINs apply there,
//!   matching the oracle's `pos = bail_end` resumption.

use std::io;

use crate::types::RuleId;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Anchor fed to the shared prefilter (11 bytes, same length as `github_pat_`).
pub(crate) const PEM_ANCHOR: &[u8] = b"-----BEGIN ";

/// Stable rule id for PEM private-key detection.
pub(crate) const PEM_RULE_ID: &str = "pem-private-key";

/// Default body-size bail-out (bytes). If the body between BEGIN and END
/// exceeds this limit, the engine emits a tag and resumes normal scanning.
pub(crate) const PEM_BAIL_OUT: usize = 16_384; // 16 KiB

/// Suffix that closes both BEGIN and END lines.
pub(crate) const PEM_DASHES: &[u8] = b"-----";

/// Private-key type labels that trigger detection. Order does not matter:
/// no label is a prefix of another, so `starts_with` matching is
/// order-independent.
pub(crate) const PEM_KEY_TYPES: &[&[u8]] = &[
    b"RSA PRIVATE KEY",
    b"EC PRIVATE KEY",
    b"DSA PRIVATE KEY",
    b"OPENSSH PRIVATE KEY",
    b"ENCRYPTED PRIVATE KEY",
    b"PRIVATE KEY", // PKCS#8 generic
];

/// Maximum length of a BEGIN/END line across all key types.
/// `-----BEGIN ENCRYPTED PRIVATE KEY-----` = 37 bytes (the longest).
pub(crate) const MAX_PEM_LINE: usize = 11 + 21 + 5; // "-----BEGIN " + "ENCRYPTED PRIVATE KEY" + "-----"

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// Data for the [`PemState::InBlock`] variant — boxed to avoid a
/// large size difference between enum variants (clippy::large_enum_variant).
pub(crate) struct PemBlockData {
    /// Incremental BLAKE3 keyed hasher over the body bytes (keyed with the
    /// engine's digest key at entry).
    pub hasher: blake3::Hasher,
    /// Running count of body bytes hashed (for bail-out).
    pub body_bytes: usize,
    /// The END marker to search for.
    pub end_marker: Vec<u8>,
    /// Small carry buffer for END-marker straddling detection.
    pub pem_carry: Vec<u8>,
}

/// PEM detector state, held in [`Session`](super::Session).
///
/// `Idle` while no private-key block is open. The engine enters `InBlock`
/// when a confirmed BEGIN's END marker has not yet arrived, and leaves it
/// on END, bail-out, or finish.
pub(crate) enum PemState {
    Idle,
    InBlock(Box<PemBlockData>),
}

impl PemState {
    pub(crate) fn is_in_block(&self) -> bool {
        matches!(self, PemState::InBlock(_))
    }
}

// ---------------------------------------------------------------------------
// PEM BEGIN confirmation
// ---------------------------------------------------------------------------

/// Result of confirming a `-----BEGIN ` candidate.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PemBeginMatch {
    /// Index into `PEM_KEY_TYPES`.
    pub key_type_idx: usize,
    /// Byte offset just past the closing `-----` of the BEGIN line.
    pub begin_line_end: usize,
}

/// Tag prefix used to detect already-redacted PEM blocks (idempotence).
const CLOAK_TAG_PREFIX: &[u8] = b"[CLOAK:";

/// Check whether the anchor at `begin_pos` is a private-key BEGIN line.
/// Returns the key-type index and the position just after the line's
/// closing dashes if confirmed; `None` otherwise.
///
/// Rejects already-redacted PEM blocks (body starts with `[CLOAK:`) so
/// that `redact(redact(S)) == redact(S)` holds for PEM.
pub(crate) fn confirm_pem_begin(buf: &[u8], begin_pos: usize) -> Option<PemBeginMatch> {
    let after_anchor = begin_pos + PEM_ANCHOR.len();
    let rest = buf.get(after_anchor..)?;
    for (i, &key_type) in PEM_KEY_TYPES.iter().enumerate() {
        if rest.starts_with(key_type) {
            let after_type = rest.get(key_type.len()..)?;
            if after_type.starts_with(PEM_DASHES) {
                let begin_line_end = after_anchor + key_type.len() + PEM_DASHES.len();
                // Idempotence: skip if the body starts with a CLOAK tag
                // (this is a previously-redacted PEM block).
                if buf
                    .get(begin_line_end..)
                    .is_some_and(|b| b.starts_with(CLOAK_TAG_PREFIX))
                {
                    return None;
                }
                return Some(PemBeginMatch {
                    key_type_idx: i,
                    begin_line_end,
                });
            }
        }
    }
    None
}

/// Build the END marker for a confirmed key type.
pub(crate) fn end_marker_for(key_type_idx: usize) -> Vec<u8> {
    let mut m = b"-----END ".to_vec();
    m.extend_from_slice(PEM_KEY_TYPES[key_type_idx]);
    m.extend_from_slice(PEM_DASHES);
    m
}

/// Window required to confirm a PEM BEGIN at a given anchor position.
/// The longest BEGIN line is `MAX_PEM_LINE` bytes, plus the bytes the
/// `[CLOAK:` idempotence guard in [`confirm_pem_begin`] inspects after
/// the line — without them a streaming push could confirm the BEGIN
/// before the guard bytes arrive and redact an already-redacted block
/// the whole-buffer path rejects (found by fuzz_pem_state).
pub(crate) fn pem_confirm_window() -> usize {
    MAX_PEM_LINE + CLOAK_TAG_PREFIX.len()
}

// ---------------------------------------------------------------------------
// PEM body processing
// ---------------------------------------------------------------------------

/// Outcome of processing a data slice while in PEM `InBlock` state.
pub(crate) enum PemBodyResult {
    /// Still accumulating — caller continues PEM mode on next push.
    Continuing,
    /// Found the END marker within the bail-out budget. The tag and the
    /// END marker line have been written. `remainder_start` is the byte
    /// offset in the *provided data* where normal scanning resumes.
    Closed {
        /// Byte offset in `data` where normal scanning resumes (after END).
        remainder_start: usize,
    },
    /// Bail-out: the body reached `PEM_BAIL_OUT` bytes (with or without an
    /// END marker in this slice). The tag covers exactly `PEM_BAIL_OUT`
    /// body bytes — identical to the whole-buffer path — and `remainder`
    /// holds every byte past the truncation point (body tail, END line,
    /// and beyond) for normal scanning.
    BailedOut { remainder: Vec<u8> },
}

/// Process a data slice while in PEM `InBlock` state.
///
/// Searches for the END marker, hashes body bytes incrementally, and
/// enforces the bail-out. The hasher must already be keyed with the
/// engine's digest key (see [`PemBlockData::hasher`]).
pub(crate) fn process_pem_body(
    state: &mut PemState,
    data: &[u8],
    out: &mut impl io::Write,
) -> io::Result<PemBodyResult> {
    let PemState::InBlock(ref mut block) = *state else {
        return Ok(PemBodyResult::Continuing);
    };
    let PemBlockData {
        hasher,
        body_bytes,
        end_marker,
        pem_carry,
    } = &mut **block;

    // Conceptually prepend pem_carry to data for searching. To avoid an
    // allocation on every push we search a combined view via a small
    // temporary buffer only when pem_carry is non-empty. pem_carry bytes
    // have NOT been hashed yet (they were retained for straddling
    // detection), so `body_bytes` counts only fully-hashed bytes.
    let carry_len = pem_carry.len();
    let mut combined: Vec<u8>;
    let search_buf: &[u8] = if carry_len == 0 {
        data
    } else {
        combined = Vec::with_capacity(carry_len + data.len());
        combined.extend_from_slice(pem_carry);
        combined.extend_from_slice(data);
        &combined
    };

    // Search for the END marker in the combined view.
    if let Some(found) = find_subsequence(search_buf, end_marker) {
        // Total body bytes up to the END marker (hashed + unhashed).
        let body_to_end = *body_bytes + found;
        if body_to_end <= PEM_BAIL_OUT {
            // Full redaction: hash the remaining body bytes up to END.
            hasher.update(&search_buf[..found]);
            *body_bytes += found;
            let digest = crate::redact::digest_from_hasher(hasher);
            let rule_id = RuleId::new(PEM_RULE_ID);
            crate::redact::write_tag(&rule_id, &digest, out)?;

            // Write the END marker line to output (markers stay visible).
            let end_line_end = found + end_marker.len();
            out.write_all(&search_buf[found..end_line_end])?;

            // Compute remainder_start relative to the original `data` slice.
            // The END marker cannot lie entirely within pem_carry (the
            // previous search would have found it), so this is ≥ 1.
            let remainder_start = end_line_end.saturating_sub(carry_len);

            *state = PemState::Idle;
            return Ok(PemBodyResult::Closed { remainder_start });
        }

        // Oversized body: truncate the redaction at PEM_BAIL_OUT — the
        // same rule as the whole-buffer path. Hash exactly the budget,
        // then hand everything past the truncation point (body tail, END
        // line, and beyond) back for normal scanning.
        let hash_more = PEM_BAIL_OUT - *body_bytes;
        hasher.update(&search_buf[..hash_more]);
        *body_bytes += hash_more;
        let digest = crate::redact::digest_from_hasher(hasher);
        let rule_id = RuleId::new(PEM_RULE_ID);
        crate::redact::write_tag(&rule_id, &digest, out)?;

        *state = PemState::Idle;
        return Ok(PemBodyResult::BailedOut {
            remainder: search_buf[hash_more..].to_vec(),
        });
    }

    // No END found. If the body would stay within the bail-out budget,
    // hash everything except the tail retained for straddling detection.
    if *body_bytes + search_buf.len() <= PEM_BAIL_OUT {
        let retain = end_marker.len().saturating_sub(1).min(search_buf.len());
        let hashable_end = search_buf.len() - retain;
        hasher.update(&search_buf[..hashable_end]);
        *body_bytes += hashable_end;
        pem_carry.clear();
        pem_carry.extend_from_slice(&search_buf[hashable_end..]);
        return Ok(PemBodyResult::Continuing);
    }

    // Bail-out mid-stream: hash exactly the remaining budget, then hand
    // everything past the truncation point back for normal scanning.
    let hash_more = PEM_BAIL_OUT - *body_bytes;
    hasher.update(&search_buf[..hash_more]);
    *body_bytes += hash_more;
    let digest = crate::redact::digest_from_hasher(hasher);
    let rule_id = RuleId::new(PEM_RULE_ID);
    crate::redact::write_tag(&rule_id, &digest, out)?;

    *state = PemState::Idle;
    Ok(PemBodyResult::BailedOut {
        remainder: search_buf[hash_more..].to_vec(),
    })
}

/// Finalize PEM state on session finish (stream ended without END marker).
/// Writes the tag for whatever body was accumulated.
pub(crate) fn finish_pem(state: &mut PemState, out: &mut impl io::Write) -> io::Result<()> {
    let PemState::InBlock(ref mut block) = *state else {
        return Ok(());
    };
    let PemBlockData {
        hasher, pem_carry, ..
    } = &mut **block;

    // Hash any remaining carry bytes.
    if !pem_carry.is_empty() {
        hasher.update(pem_carry);
    }

    let digest = crate::redact::digest_from_hasher(hasher);
    let rule_id = RuleId::new(PEM_RULE_ID);
    crate::redact::write_tag(&rule_id, &digest, out)?;

    *state = PemState::Idle;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Simple byte-subsequence search (no SIMD — END markers are rare).
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- confirm_pem_begin -------------------------------------------------

    #[test]
    fn confirm_rsa_private_key() {
        let buf = b"-----BEGIN RSA PRIVATE KEY-----\ndata";
        let m = confirm_pem_begin(buf, 0).expect("should confirm");
        assert_eq!(m.key_type_idx, 0); // RSA PRIVATE KEY
        assert_eq!(m.begin_line_end, 31);
    }

    #[test]
    fn confirm_ec_private_key() {
        let buf = b"prefix-----BEGIN EC PRIVATE KEY-----\n";
        let m = confirm_pem_begin(buf, 6).expect("should confirm");
        assert_eq!(PEM_KEY_TYPES[m.key_type_idx], b"EC PRIVATE KEY");
        assert_eq!(m.begin_line_end, 6 + 11 + 14 + 5);
    }

    #[test]
    fn confirm_pkcs8_generic() {
        let buf = b"-----BEGIN PRIVATE KEY-----\n";
        let m = confirm_pem_begin(buf, 0).expect("should confirm");
        assert_eq!(PEM_KEY_TYPES[m.key_type_idx], b"PRIVATE KEY");
    }

    #[test]
    fn confirm_encrypted_private_key() {
        let buf = b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n";
        let m = confirm_pem_begin(buf, 0).expect("should confirm");
        assert_eq!(PEM_KEY_TYPES[m.key_type_idx], b"ENCRYPTED PRIVATE KEY");
    }

    #[test]
    fn confirm_openssh_private_key() {
        let buf = b"-----BEGIN OPENSSH PRIVATE KEY-----\n";
        let m = confirm_pem_begin(buf, 0).expect("should confirm");
        assert_eq!(PEM_KEY_TYPES[m.key_type_idx], b"OPENSSH PRIVATE KEY");
    }

    #[test]
    fn reject_certificate() {
        let buf = b"-----BEGIN CERTIFICATE-----\n";
        assert!(confirm_pem_begin(buf, 0).is_none());
    }

    #[test]
    fn reject_public_key() {
        let buf = b"-----BEGIN PUBLIC KEY-----\n";
        assert!(confirm_pem_begin(buf, 0).is_none());
    }

    #[test]
    fn reject_truncated_begin() {
        let buf = b"-----BEGIN RSA PRIV";
        assert!(confirm_pem_begin(buf, 0).is_none());
    }

    #[test]
    fn reject_case_mismatch() {
        let buf = b"-----BEGIN rsa private key-----\n";
        assert!(confirm_pem_begin(buf, 0).is_none());
    }

    #[test]
    fn reject_missing_trailing_dashes() {
        let buf = b"-----BEGIN RSA PRIVATE KEY\n";
        assert!(confirm_pem_begin(buf, 0).is_none());
    }

    // --- end_marker_for ----------------------------------------------------

    #[test]
    fn end_marker_rsa() {
        assert_eq!(end_marker_for(0), b"-----END RSA PRIVATE KEY-----".to_vec());
    }

    #[test]
    fn end_marker_pkcs8() {
        let idx = PEM_KEY_TYPES
            .iter()
            .position(|&t| t == b"PRIVATE KEY")
            .unwrap();
        assert_eq!(end_marker_for(idx), b"-----END PRIVATE KEY-----".to_vec());
    }

    // --- process_pem_body --------------------------------------------------

    fn test_key() -> [u8; 32] {
        blake3::derive_key("cloak digest key", b"pem-test-key")
    }

    #[test]
    fn body_with_immediate_end() {
        let key = test_key();
        let body = b"body\n-----END RSA PRIVATE KEY-----rest";
        let mut state = PemState::InBlock(Box::new(PemBlockData {
            hasher: blake3::Hasher::new_keyed(&key),
            body_bytes: 0,
            end_marker: end_marker_for(0),
            pem_carry: Vec::new(),
        }));
        let mut out = Vec::new();
        let result = process_pem_body(&mut state, body, &mut out).unwrap();
        match result {
            PemBodyResult::Closed { remainder_start } => {
                // "rest" starts at position 34 in body.
                assert_eq!(&body[remainder_start..], b"rest");
            }
            _ => panic!("expected Closed"),
        }
        assert!(matches!(state, PemState::Idle));
        // Output should contain tag + END marker.
        let out_str = String::from_utf8_lossy(&out);
        assert!(out_str.contains("[CLOAK:pem-private-key:"));
        assert!(out_str.contains("-----END RSA PRIVATE KEY-----"));
    }

    #[test]
    fn body_without_end_continues() {
        let key = test_key();
        let body = b"some base64 data without end marker";
        let mut state = PemState::InBlock(Box::new(PemBlockData {
            hasher: blake3::Hasher::new_keyed(&key),
            body_bytes: 0,
            end_marker: end_marker_for(0),
            pem_carry: Vec::new(),
        }));
        let mut out = Vec::new();
        let result = process_pem_body(&mut state, body, &mut out).unwrap();
        assert!(matches!(result, PemBodyResult::Continuing));
        assert!(state.is_in_block());
        assert!(out.is_empty(), "no output until END or bail-out");
    }

    #[test]
    fn bail_out_at_16kib() {
        let key = test_key();
        // Feed more than 16 KiB of body data without an END marker.
        let big_body = vec![b'A'; PEM_BAIL_OUT + 100];
        let mut state = PemState::InBlock(Box::new(PemBlockData {
            hasher: blake3::Hasher::new_keyed(&key),
            body_bytes: 0,
            end_marker: end_marker_for(0),
            pem_carry: Vec::new(),
        }));
        let mut out = Vec::new();
        let result = process_pem_body(&mut state, &big_body, &mut out).unwrap();
        match result {
            // The tag covers exactly PEM_BAIL_OUT body bytes; the 100-byte
            // excess goes back through normal scanning.
            PemBodyResult::BailedOut { remainder } => {
                assert_eq!(remainder, big_body[PEM_BAIL_OUT..].to_vec());
            }
            _ => panic!("expected BailedOut"),
        }
        assert!(matches!(state, PemState::Idle));
        let out_str = String::from_utf8_lossy(&out);
        assert!(out_str.contains("[CLOAK:pem-private-key:"));
    }

    #[test]
    fn bail_out_digest_covers_exactly_16kib() {
        // M4: the streaming bail-out digest must equal the whole-buffer
        // digest — hash exactly PEM_BAIL_OUT bytes, no more.
        let key = test_key();
        let big_body = vec![b'A'; PEM_BAIL_OUT + 100];
        let mut state = PemState::InBlock(Box::new(PemBlockData {
            hasher: blake3::Hasher::new_keyed(&key),
            body_bytes: 0,
            end_marker: end_marker_for(0),
            pem_carry: Vec::new(),
        }));
        let mut out = Vec::new();
        process_pem_body(&mut state, &big_body, &mut out).unwrap();
        let streaming_digest = out; // "[CLOAK:pem-private-key:xxxx]"

        let expected_digest = crate::redact::compute_digest(&big_body[..PEM_BAIL_OUT], &key);
        let expected_tag = crate::redact::format_tag(&RuleId::new(PEM_RULE_ID), &expected_digest);
        assert_eq!(streaming_digest, expected_tag.as_bytes());
    }

    #[test]
    fn oversized_body_with_end_truncates_at_16kib() {
        // END present but the body exceeds the budget: the redaction is
        // truncated at PEM_BAIL_OUT and the tail + END line go back for
        // normal scanning (whole-buffer parity).
        let key = test_key();
        let end = b"-----END RSA PRIVATE KEY-----";
        let mut body = vec![b'A'; PEM_BAIL_OUT + 50];
        body.extend_from_slice(end);
        body.extend_from_slice(b"after");
        let mut state = PemState::InBlock(Box::new(PemBlockData {
            hasher: blake3::Hasher::new_keyed(&key),
            body_bytes: 0,
            end_marker: end.to_vec(),
            pem_carry: Vec::new(),
        }));
        let mut out = Vec::new();
        let result = process_pem_body(&mut state, &body, &mut out).unwrap();
        match result {
            PemBodyResult::BailedOut { remainder } => {
                assert_eq!(remainder, body[PEM_BAIL_OUT..].to_vec());
                assert!(remainder.ends_with(b"after"));
            }
            _ => panic!("expected BailedOut"),
        }
        assert!(matches!(state, PemState::Idle));
        // Only the tag — the END line is part of the remainder, not output.
        let expected_digest = crate::redact::compute_digest(&body[..PEM_BAIL_OUT], &key);
        let expected_tag = crate::redact::format_tag(&RuleId::new(PEM_RULE_ID), &expected_digest);
        assert_eq!(out, expected_tag.as_bytes());
    }

    #[test]
    fn empty_body_closes_with_tag() {
        let key = test_key();
        let body = b"-----END RSA PRIVATE KEY-----rest";
        let mut state = PemState::InBlock(Box::new(PemBlockData {
            hasher: blake3::Hasher::new_keyed(&key),
            body_bytes: 0,
            end_marker: end_marker_for(0),
            pem_carry: Vec::new(),
        }));
        let mut out = Vec::new();
        let result = process_pem_body(&mut state, body, &mut out).unwrap();
        match result {
            PemBodyResult::Closed { remainder_start } => {
                assert_eq!(&body[remainder_start..], b"rest");
            }
            _ => panic!("expected Closed"),
        }
        // Zero body bytes → digest of the empty slice.
        let expected_digest = crate::redact::compute_digest(b"", &key);
        let expected_tag = crate::redact::format_tag(&RuleId::new(PEM_RULE_ID), &expected_digest);
        let out_str = String::from_utf8_lossy(&out);
        assert!(out_str.starts_with(&expected_tag));
        assert!(out_str.ends_with("-----END RSA PRIVATE KEY-----"));
    }

    #[test]
    fn end_marker_straddling_two_pushes() {
        let key = test_key();
        let end = b"-----END RSA PRIVATE KEY-----";
        // Split the END marker across two pushes.
        let part1 = b"body data-----END RSA PRI";
        let part2 = b"VATE KEY-----after";
        let mut state = PemState::InBlock(Box::new(PemBlockData {
            hasher: blake3::Hasher::new_keyed(&key),
            body_bytes: 0,
            end_marker: end.to_vec(),
            pem_carry: Vec::new(),
        }));
        let mut out = Vec::new();

        // First push: END not found, retains tail in pem_carry.
        let r1 = process_pem_body(&mut state, part1, &mut out).unwrap();
        assert!(matches!(r1, PemBodyResult::Continuing));

        // Second push: END found across the carry boundary.
        let r2 = process_pem_body(&mut state, part2, &mut out).unwrap();
        match r2 {
            PemBodyResult::Closed { remainder_start } => {
                assert_eq!(&part2[remainder_start..], b"after");
            }
            _ => panic!("expected Closed on second push"),
        }
        let out_str = String::from_utf8_lossy(&out);
        assert!(out_str.contains("[CLOAK:pem-private-key:"));
        assert!(out_str.contains("-----END RSA PRIVATE KEY-----"));
    }

    #[test]
    fn finish_pem_without_end_marker() {
        let key = test_key();
        let mut state = PemState::InBlock(Box::new(PemBlockData {
            hasher: blake3::Hasher::new_keyed(&key),
            body_bytes: 100,
            end_marker: end_marker_for(0),
            pem_carry: b"tail".to_vec(),
        }));
        let mut out = Vec::new();
        finish_pem(&mut state, &mut out).unwrap();
        assert!(matches!(state, PemState::Idle));
        let out_str = String::from_utf8_lossy(&out);
        assert!(out_str.contains("[CLOAK:pem-private-key:"));
    }
}
