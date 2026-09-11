//! Deliberately naive whole-buffer redaction — the differential-test oracle
//! (docs/03-guarantee-and-testing.md: `redact_reference`).
//!
//! Independent of the production matcher **by design**: hand-rolled O(n·m)
//! anchor search, per-rule confirm loops (no regex), naive group-absorption
//! overlap merge. It shares ONLY the golden-tested digest/tag primitives
//! (`crate::redact`). Rule constants are re-declared inline — duplication is
//! the point of an oracle; a unit test cross-checks them against
//! `rules::CATALOG` so a typo on either side is caught without coupling the
//! algorithms.
//!
//! Re-exported `#[doc(hidden)]` from lib.rs purely so integration tests can
//! reach it — this module is **not** part of the public API contract.

use std::collections::BTreeMap;

use crate::types::{RuleId, Stats};

/// Rule indices — must mirror catalog order (cross-checked by unit test).
const GITHUB: usize = 0;
const GITLAB: usize = 1;
const NPM: usize = 2;
const AWS_ACCESS: usize = 3;
const GCP_API: usize = 4;
const PYPI: usize = 5;
const AWS_SECRET: usize = 6;
const AZURE: usize = 7;
const JWT: usize = 8;
const CONN_STRING: usize = 9;
const EMAIL: usize = 10;
const IPV4: usize = 11;
const IPV6: usize = 12;
const CREDIT_CARD: usize = 13;
const PHONE_INTL: usize = 14;
/// PEM is a separate layer, not in CATALOG — lives after catalog indices.
const PEM: usize = 15;

const RULE_IDS: [&str; 16] = [
    "github-token",
    "gitlab-token",
    "npm-token",
    "aws-access-key",
    "gcp-api-key",
    "pypi-token",
    "aws-secret-key",
    "azure-style-token",
    "jwt",
    "connection-string",
    "email",
    "ipv4",
    "ipv6",
    "credit-card",
    "phone-intl",
    "pem-private-key",
];

const GITHUB_PREFIXES: [&[u8]; 6] = [b"ghp_", b"gho_", b"ghs_", b"ghu_", b"ghr_", b"github_pat_"];
const GITLAB_PREFIXES: [&[u8]; 3] = [b"glpat-", b"glrt-", b"gldt-"];
const NPM_PREFIX: &[u8] = b"npm_";
const AWS_PREFIXES: [&[u8]; 2] = [b"AKIA", b"ASIA"];
const GCP_PREFIX: &[u8] = b"AIza";
const PYPI_PREFIX: &[u8] = b"pypi-";
const CONN_SCHEMES: [&[u8]; 8] = [
    b"postgres",
    b"postgresql",
    b"mysql",
    b"mongodb",
    b"mongodb+srv",
    b"redis",
    b"amqp",
    b"amqps",
];

const GITHUB_CLASSIC_BODY: usize = 36;
const GITHUB_PAT_MIN: usize = 36;
const GITLAB_MIN: usize = 20;
const NPM_BODY: usize = 36;
const AWS_BODY: usize = 16;
const GCP_BODY: usize = 35;
const PYPI_MIN: usize = 50;
const BODY_CAP: usize = 255;

/// One confirmed match, pre-merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RefMatch {
    start: usize,
    end: usize,
    rule: usize,
}

// ── Independent CRC32 + base62 (oracle reimplementation, no shared code) ──

/// CRC32/ISO-HDLC lookup table (polynomial 0xEDB88320, reflected).
/// Precomputed at compile time — no dependency on `crc32fast`.
const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut crc = i;
        let mut j = 0;
        while j < 8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
};

/// Independent CRC32 implementation for the oracle. Uses the precomputed
/// lookup table, not the `crc32fast` crate.
fn crc32_oracle(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        let idx = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[idx];
    }
    crc ^ 0xFFFFFFFF
}

/// Decode exactly 6 base62 characters to a u32 (independent of
/// `validators::base62_decode_6`).
fn base62_decode_6_oracle(chars: &[u8]) -> Option<u32> {
    if chars.len() != 6 {
        return None;
    }
    let mut value: u64 = 0;
    for &b in chars {
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as u64,
            b'A'..=b'Z' => (b - b'A') as u64 + 10,
            b'a'..=b'z' => (b - b'a') as u64 + 36,
            _ => return None,
        };
        value = value * 62 + digit;
    }
    u32::try_from(value).ok()
}

/// Validate CRC32 checksum in the oracle path.
fn validate_crc32_oracle(entropy: &[u8], checksum: &[u8]) -> bool {
    let expected = crc32_oracle(entropy);
    base62_decode_6_oracle(checksum).is_some_and(|decoded| decoded == expected)
}

fn is_base62_oracle(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

fn is_github_body(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_gitlab_body(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn is_npm_body(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

fn is_aws_body(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit()
}

fn is_gcp_body(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn is_pypi_body(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn confirm_github(input: &[u8], start: usize) -> Option<usize> {
    let rest = &input[start..];
    let prefix = GITHUB_PREFIXES.iter().find(|p| rest.starts_with(p))?;
    let body = &rest[prefix.len()..];

    if *prefix == b"github_pat_" {
        // Fine-grained: shape-only, greedy [0-9A-Za-z_]{36,255}.
        let mut taken = 0;
        while taken < body.len() && taken < BODY_CAP && is_github_body(body[taken]) {
            taken += 1;
        }
        (taken >= GITHUB_PAT_MIN).then_some(start + prefix.len() + taken)
    } else {
        // Classic: exactly 36 base62 chars, CRC32-validated.
        if body.len() < GITHUB_CLASSIC_BODY {
            return None;
        }
        let body36 = &body[..GITHUB_CLASSIC_BODY];
        if !body36.iter().all(|&b| is_base62_oracle(b)) {
            return None;
        }
        let entropy = &body36[..30];
        let checksum = &body36[30..];
        if !validate_crc32_oracle(entropy, checksum) {
            return None;
        }
        Some(start + prefix.len() + GITHUB_CLASSIC_BODY)
    }
}

fn confirm_gitlab(input: &[u8], start: usize) -> Option<usize> {
    let rest = &input[start..];
    let prefix = GITLAB_PREFIXES.iter().find(|p| rest.starts_with(p))?;
    let body = &rest[prefix.len()..];
    let mut taken = 0;
    while taken < body.len() && taken < BODY_CAP && is_gitlab_body(body[taken]) {
        taken += 1;
    }
    (taken >= GITLAB_MIN).then_some(start + prefix.len() + taken)
}

fn confirm_npm(input: &[u8], start: usize) -> Option<usize> {
    let rest = &input[start..];
    if !rest.starts_with(NPM_PREFIX) {
        return None;
    }
    let body = &rest[NPM_PREFIX.len()..];
    if body.len() < NPM_BODY {
        return None;
    }
    let body36 = &body[..NPM_BODY];
    if !body36.iter().all(|&b| is_npm_body(b)) {
        return None;
    }
    // CRC32 validation: 30 entropy + 6 checksum.
    let entropy = &body36[..30];
    let checksum = &body36[30..];
    if !validate_crc32_oracle(entropy, checksum) {
        return None;
    }
    Some(start + NPM_PREFIX.len() + NPM_BODY)
}

fn confirm_aws_access(input: &[u8], start: usize) -> Option<usize> {
    let rest = &input[start..];
    let prefix = AWS_PREFIXES.iter().find(|p| rest.starts_with(p))?;
    let body = &rest[prefix.len()..];
    let mut taken = 0;
    while taken < body.len() && taken < AWS_BODY && is_aws_body(body[taken]) {
        taken += 1;
    }
    (taken == AWS_BODY).then_some(start + prefix.len() + taken)
}

fn confirm_gcp_api(input: &[u8], start: usize) -> Option<usize> {
    let rest = &input[start..];
    if !rest.starts_with(GCP_PREFIX) {
        return None;
    }
    let body = &rest[GCP_PREFIX.len()..];
    let mut taken = 0;
    while taken < body.len() && taken < GCP_BODY && is_gcp_body(body[taken]) {
        taken += 1;
    }
    (taken == GCP_BODY).then_some(start + GCP_PREFIX.len() + taken)
}

fn confirm_pypi(input: &[u8], start: usize) -> Option<usize> {
    let rest = &input[start..];
    if !rest.starts_with(PYPI_PREFIX) {
        return None;
    }
    let body = &rest[PYPI_PREFIX.len()..];
    let mut taken = 0;
    while taken < body.len() && taken < BODY_CAP && is_pypi_body(body[taken]) {
        taken += 1;
    }
    (taken >= PYPI_MIN).then_some(start + PYPI_PREFIX.len() + taken)
}

// --- Context-keyed: return (redact_start, redact_end) ---

fn confirm_aws_secret(input: &[u8], start: usize) -> Option<(usize, usize)> {
    if start >= input.len() {
        return None;
    }
    let rest = &input[start..];
    // Must start with one of the anchor strings.
    let key_end = if rest.starts_with(b"aws_secret_access_key") {
        start + 21
    } else if rest.starts_with(b"SecretAccessKey") {
        start + 15
    } else {
        return None;
    };
    // Non-alnum boundary before the key name (not mid-word).
    if start > 0 && input[start - 1].is_ascii_alphanumeric() {
        return None;
    }
    let mut pos = key_end;
    // Skip closing quotes and whitespace before separator.
    while pos < input.len()
        && (input[pos] == b'"' || input[pos] == b'\'' || input[pos] == b' ' || input[pos] == b'\t')
    {
        pos += 1;
    }
    if pos >= input.len() || (input[pos] != b'=' && input[pos] != b':') {
        return None;
    }
    pos += 1;
    while pos < input.len()
        && (input[pos] == b' ' || input[pos] == b'\t' || input[pos] == b'"' || input[pos] == b'\'')
    {
        pos += 1;
    }
    let value_start = pos;
    let mut taken = 0;
    while pos < input.len() && taken < 40 && is_base64_oracle(input[pos]) {
        pos += 1;
        taken += 1;
    }
    (taken == 40).then_some((value_start, pos))
}

fn is_base64_oracle(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
}

fn confirm_azure(input: &[u8], start: usize) -> Option<(usize, usize)> {
    if start >= input.len() {
        return None;
    }
    let rest = &input[start..];
    let key_len = if rest.len() >= 11 && rest[..11].eq_ignore_ascii_case(b"accountkey=") {
        11
    } else if rest.len() >= 4 && rest[..4].eq_ignore_ascii_case(b"sig=") {
        4
    } else {
        return None;
    };
    let value_start = start + key_len;
    let mut pos = value_start;
    let mut taken = 0;
    while pos < input.len() && taken < 255 && is_azure_val_oracle(input[pos]) {
        pos += 1;
        taken += 1;
    }
    (taken >= 20).then_some((value_start, pos))
}

fn is_azure_val_oracle(b: u8) -> bool {
    match b {
        b';' | b'&' | b':' | b'@' | b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'' => false,
        _ => b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' || b == b'%',
    }
}

fn confirm_jwt_oracle(input: &[u8], start: usize) -> Option<usize> {
    let rest = &input[start..];
    let limit = rest.len().min(2048);
    let rest = &rest[..limit];
    let dot1 = rest.iter().position(|&b| b == b'.')?;
    if dot1 == 0 {
        return None;
    }
    let after1 = dot1 + 1;
    let dot2 = rest[after1..]
        .iter()
        .position(|&b| b == b'.')
        .map(|p| after1 + p)?;
    if dot2 == after1 {
        return None;
    }
    let after2 = dot2 + 1;
    let mut sig_end = after2;
    while sig_end < rest.len() && is_b64url_oracle(rest[sig_end]) {
        sig_end += 1;
    }
    if sig_end == after2 {
        return None;
    }
    let header = &rest[..dot1];
    let payload = &rest[after1..dot2];
    let sig = &rest[after2..sig_end];
    if !header.iter().all(|&b| is_b64url_oracle(b)) {
        return None;
    }
    if !payload.iter().all(|&b| is_b64url_oracle(b)) {
        return None;
    }
    if !sig.iter().all(|&b| is_b64url_oracle(b)) {
        return None;
    }
    let decoded = b64url_decode_oracle(header)?;
    if decoded.len() < 2 || decoded[0] != b'{' || decoded[1] != b'"' {
        return None;
    }
    Some(start + sig_end)
}

fn is_b64url_oracle(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

fn b64url_decode_oracle(input: &[u8]) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut accum: u32 = 0;
    let mut bits: u32 = 0;
    for &b in input {
        let val = match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a' + 26) as u32,
            b'0'..=b'9' => (b - b'0' + 52) as u32,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        accum = (accum << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            buf.push((accum >> bits) as u8);
            accum &= (1 << bits) - 1;
        }
    }
    Some(buf)
}

fn confirm_connstring(input: &[u8], start: usize) -> Option<(usize, usize)> {
    // Must have `://` at this position.
    if start + 2 >= input.len()
        || input[start] != b':'
        || input[start + 1] != b'/'
        || input[start + 2] != b'/'
    {
        return None;
    }
    // `://` at start. Look backward for scheme.
    let mut scheme_start = start;
    while scheme_start > 0 && is_scheme_oracle(input[scheme_start - 1]) {
        scheme_start -= 1;
    }
    let scheme = &input[scheme_start..start];
    if !CONN_SCHEMES.iter().any(|s| scheme.eq_ignore_ascii_case(s)) {
        return None;
    }
    let after = start + 3;
    let at_pos = input[after..]
        .iter()
        .position(|&b| b == b'@')
        .map(|p| after + p)?;
    if at_pos - after > 300 {
        return None;
    }
    let userinfo = &input[after..at_pos];
    let colon_pos = userinfo.iter().position(|&b| b == b':')?;
    let pw_start = after + colon_pos + 1;
    let pw_end = at_pos;
    if pw_start >= pw_end {
        return None;
    }
    Some((pw_start, pw_end))
}

fn is_scheme_oracle(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.'
}

fn confirm_email_oracle(input: &[u8], at_pos: usize) -> Option<(usize, usize)> {
    // Must actually be an `@` at this position (oracle is called at every offset).
    if at_pos >= input.len() || input[at_pos] != b'@' {
        return None;
    }
    // Backward: local part.
    let mut local_start = at_pos;
    while local_start > 0 && is_email_local_oracle(input[local_start - 1]) {
        local_start -= 1;
    }
    if local_start == at_pos {
        return None;
    }
    if input[local_start] == b'.' || input[at_pos - 1] == b'.' {
        return None;
    }
    // Reject URL credential context: local preceded by `:` or `/`.
    if local_start > 0 && (input[local_start - 1] == b':' || input[local_start - 1] == b'/') {
        return None;
    }
    // Forward: domain.
    let domain_start = at_pos + 1;
    let mut domain_end = domain_start;
    while domain_end < input.len() && is_email_domain_oracle(input[domain_end]) {
        domain_end += 1;
    }
    let domain = &input[domain_start..domain_end];
    let last_dot = domain.iter().rposition(|&b| b == b'.')?;
    let tld = &domain[last_dot + 1..];
    if tld.len() < 2 || !tld.iter().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    for label in domain.split(|&b| b == b'.') {
        if label.is_empty() || label[0] == b'-' || label[label.len() - 1] == b'-' {
            return None;
        }
    }
    Some((local_start, domain_end))
}

fn is_email_local_oracle(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'+' || b == b'-' || b == b'_'
}
fn is_email_domain_oracle(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-'
}

fn confirm_ipv4_oracle(input: &[u8], dot_pos: usize) -> Option<(usize, usize)> {
    // Only called at digit-dot positions (oracle scans every offset).
    if dot_pos >= input.len()
        || !input[dot_pos].is_ascii_digit()
        || dot_pos + 1 >= input.len()
        || input[dot_pos + 1] != b'.'
    {
        return None;
    }
    // The anchor is a digit-dot pair. Back up to find the first octet.
    let earliest = dot_pos.saturating_sub(11);
    let mut start = dot_pos;
    while start > earliest && (input[start - 1].is_ascii_digit() || input[start - 1] == b'.') {
        start -= 1;
    }
    if start > 0 && input[start - 1].is_ascii_digit() {
        return None;
    }
    let mut pos = start;
    let mut octets = 0;
    while octets < 4 && pos < input.len() {
        let ostart = pos;
        while pos < input.len() && input[pos].is_ascii_digit() {
            pos += 1;
        }
        let olen = pos - ostart;
        if olen == 0 || olen > 3 {
            return None;
        }
        if olen > 1 && input[ostart] == b'0' {
            return None;
        }
        let val = parse_u8_ref(&input[ostart..pos]);
        if val > 255 {
            return None;
        }
        octets += 1;
        if octets < 4 {
            if pos >= input.len() || input[pos] != b'.' {
                return None;
            }
            pos += 1;
        }
    }
    if octets != 4 {
        return None;
    }
    if pos < input.len() && input[pos].is_ascii_digit() {
        return None;
    }
    if pos < input.len() && input[pos] == b'.' {
        return None;
    }
    Some((start, pos))
}

fn parse_u8_ref(bytes: &[u8]) -> u16 {
    let mut v: u16 = 0;
    for &b in bytes {
        v = v * 10 + (b - b'0') as u16;
    }
    v
}

fn confirm_ipv6_oracle(input: &[u8], dc_pos: usize) -> Option<(usize, usize)> {
    // The anchor `::` is 2 bytes — need at least 2 bytes at dc_pos.
    if dc_pos + 1 >= input.len() || input[dc_pos] != b':' || input[dc_pos + 1] != b':' {
        return None;
    }
    let mut start = dc_pos;
    while start > 0 && is_ipv6_char_oracle(input[start - 1]) {
        start -= 1;
    }
    if start > 0 && input[start - 1].is_ascii_alphanumeric() {
        return None;
    }
    let mut end = dc_pos + 2;
    while end < input.len() && is_ipv6_ext_oracle(input[end]) {
        end += 1;
    }
    if end - start > 45 {
        return None;
    }
    if end < input.len() && input[end].is_ascii_alphanumeric() {
        return None;
    }
    let addr = &input[start..end];
    if !validate_ipv6_oracle(addr) {
        return None;
    }
    Some((start, end))
}

fn is_ipv6_char_oracle(b: u8) -> bool {
    b.is_ascii_hexdigit() || b == b':'
}
fn is_ipv6_ext_oracle(b: u8) -> bool {
    b.is_ascii_hexdigit() || b == b':' || b == b'.'
}

fn validate_ipv6_oracle(addr: &[u8]) -> bool {
    // Use the same logic as validators.rs but independently.
    let dc = addr.windows(2).position(|w| w == b"::");
    match dc {
        None => {
            let groups: Vec<&[u8]> = addr.split(|&b| b == b':').collect();
            groups.len() == 8 && groups.iter().all(|g| is_hex_grp(g))
        }
        Some(pos) => {
            // Check no second `::`
            if addr[pos + 2..].windows(2).any(|w| w == b"::") {
                return false;
            }
            let left: Vec<&[u8]> = if pos == 0 {
                vec![]
            } else {
                addr[..pos].split(|&b| b == b':').collect()
            };
            let right_bytes = &addr[pos + 2..];
            let right: Vec<&[u8]> = if right_bytes.is_empty() {
                vec![]
            } else {
                right_bytes.split(|&b| b == b':').collect()
            };
            let total = left.len() + right.len();
            if total > 7 {
                return false;
            }
            if let Some(last) = right.last()
                && last.contains(&b'.')
            {
                let v4_groups = left.len() + right.len() - 1;
                return v4_groups <= 6
                    && left.iter().all(|g| is_hex_grp(g))
                    && right[..right.len() - 1].iter().all(|g| is_hex_grp(g))
                    && is_v4_suffix_oracle(last);
            }
            left.iter().all(|g| is_hex_grp(g)) && right.iter().all(|g| is_hex_grp(g))
        }
    }
}
fn is_hex_grp(g: &[u8]) -> bool {
    !g.is_empty() && g.len() <= 4 && g.iter().all(|b| b.is_ascii_hexdigit())
}
fn is_v4_suffix_oracle(bytes: &[u8]) -> bool {
    let s = std::str::from_utf8(bytes).ok();
    s.is_some_and(|s| {
        let parts: Vec<&str> = s.split('.').collect();
        parts.len() == 4
            && parts.iter().all(|p| {
                !p.is_empty()
                    && p.len() <= 3
                    && (p.len() == 1 || !p.starts_with('0'))
                    && p.parse::<u16>().is_ok_and(|v| v <= 255)
            })
    })
}

fn confirm_credit_card_oracle(input: &[u8], start: usize) -> Option<usize> {
    if start > 0 && input[start - 1].is_ascii_digit() {
        return None;
    }
    let rest = &input[start..];
    let limit = rest.len().min(25);
    let mut digits = Vec::with_capacity(19);
    let mut end = 0;
    for &b in &rest[..limit] {
        if b.is_ascii_digit() {
            digits.push(b);
            end += 1;
            if digits.len() > 19 {
                break;
            }
        } else if b == b' ' || b == b'-' {
            if digits.is_empty() {
                break;
            }
            end += 1;
        } else {
            break;
        }
    }
    let abs_end = start + end;
    if abs_end < input.len() && input[abs_end].is_ascii_digit() {
        return None;
    }
    if end > 0 && !rest[end - 1].is_ascii_digit() {
        end -= 1;
    }
    if digits.len() < 13 || digits.len() > 19 {
        return None;
    }
    if !iin_oracle(&digits) {
        return None;
    }
    if !luhn_oracle(&digits) {
        return None;
    }
    Some(start + end)
}

fn luhn_oracle(digits: &[u8]) -> bool {
    let mut sum: u32 = 0;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut val = (d - b'0') as u32;
        if double {
            val *= 2;
            if val > 9 {
                val -= 9;
            }
        }
        sum += val;
        double = !double;
    }
    sum.is_multiple_of(10)
}

fn iin_oracle(digits: &[u8]) -> bool {
    if digits.is_empty() {
        return false;
    }
    match digits[0] {
        b'4' => true,
        b'3' if digits.len() >= 2 && (digits[1] == b'4' || digits[1] == b'7') => true,
        b'5' if digits.len() >= 2 && digits[1] >= b'1' && digits[1] <= b'5' => true,
        b'6' if digits.len() >= 2 => {
            if digits[1] == b'5' {
                return true;
            }
            digits.len() >= 4 && digits[1] == b'0' && digits[2] == b'1' && digits[3] == b'1'
        }
        _ => false,
    }
}

fn confirm_phone_oracle(input: &[u8], start: usize) -> Option<usize> {
    if start > 0 && input[start - 1].is_ascii_alphanumeric() {
        return None;
    }
    if input[start] != b'+' {
        return None;
    }
    let mut pos = start + 1;
    let mut digit_count = 0;
    let limit = input.len().min(start + 25);
    while pos < limit && input[pos].is_ascii_digit() {
        digit_count += 1;
        pos += 1;
    }
    if digit_count == 0 {
        return None;
    }
    while pos < limit {
        let b = input[pos];
        if b.is_ascii_digit() {
            digit_count += 1;
            pos += 1;
        } else if (b == b' ' || b == b'-' || b == b'.')
            && pos + 1 < limit
            && input[pos + 1].is_ascii_digit()
        {
            pos += 1;
        } else {
            break;
        }
    }
    if !(7..=15).contains(&digit_count) {
        return None;
    }
    if pos < input.len() && input[pos].is_ascii_digit() {
        return None;
    }
    Some(pos)
}

// PEM constants (oracle-independent re-declarations, cross-checked by test).
const PEM_BEGIN: &[u8] = b"-----BEGIN ";
const PEM_DASHES: &[u8] = b"-----";
const PEM_BAIL_OUT: usize = 16_384;
const PEM_KEY_TYPES: [&[u8]; 6] = [
    b"RSA PRIVATE KEY",
    b"EC PRIVATE KEY",
    b"DSA PRIVATE KEY",
    b"OPENSSH PRIVATE KEY",
    b"ENCRYPTED PRIVATE KEY",
    b"PRIVATE KEY",
];

/// Find all PEM private-key blocks. Returns body spans (between BEGIN and
/// END markers). Enforces bail-out at `PEM_BAIL_OUT` bytes.
fn find_pem_blocks(input: &[u8]) -> Vec<RefMatch> {
    let mut blocks = Vec::new();
    let mut pos = 0;
    while pos < input.len() {
        // Look for -----BEGIN
        if let Some(offset) = find_bytes(&input[pos..], PEM_BEGIN) {
            let begin_start = pos + offset;
            let after_begin = begin_start + PEM_BEGIN.len();
            // Check if it's a private key type.
            if let Some((begin_line_end, key_type)) = confirm_pem_begin_ref(input, after_begin) {
                // Body starts after the BEGIN line.
                let body_start = begin_line_end;
                // Look for the matching END marker.
                let mut end_marker = b"-----END ".to_vec();
                end_marker.extend_from_slice(key_type);
                end_marker.extend_from_slice(PEM_DASHES);

                if let Some(end_offset) = find_bytes(&input[body_start..], &end_marker) {
                    let body_end = body_start + end_offset;
                    let actual_body_len = body_end - body_start;
                    if actual_body_len <= PEM_BAIL_OUT {
                        blocks.push(RefMatch {
                            start: body_start,
                            end: body_end,
                            rule: PEM,
                        });
                        pos = body_end + end_marker.len();
                        continue;
                    } else {
                        // Bail-out: redact first PEM_BAIL_OUT bytes of body.
                        let bail_end = body_start + PEM_BAIL_OUT;
                        blocks.push(RefMatch {
                            start: body_start,
                            end: bail_end,
                            rule: PEM,
                        });
                        pos = bail_end;
                        continue;
                    }
                } else {
                    // No END marker: bail-out the entire remaining body.
                    let bail_end = (body_start + PEM_BAIL_OUT).min(input.len());
                    blocks.push(RefMatch {
                        start: body_start,
                        end: bail_end,
                        rule: PEM,
                    });
                    pos = bail_end;
                    continue;
                }
            }
            pos = after_begin;
        } else {
            break;
        }
    }
    blocks
}

fn confirm_pem_begin_ref(input: &[u8], after_begin: usize) -> Option<(usize, &'static [u8])> {
    let rest = input.get(after_begin..)?;
    for &key_type in &PEM_KEY_TYPES {
        if rest.starts_with(key_type) {
            let after_type = rest.get(key_type.len()..)?;
            if after_type.starts_with(PEM_DASHES) {
                let begin_line_end = after_begin + key_type.len() + PEM_DASHES.len();
                // Idempotence: skip already-redacted PEM blocks.
                if input
                    .get(begin_line_end..)
                    .is_some_and(|b| b.starts_with(b"[CLOAK:"))
                {
                    return None;
                }
                return Some((begin_line_end, key_type));
            }
        }
    }
    None
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Check if a position falls inside any PEM body span.
fn is_in_pem_region(pos: usize, pem_blocks: &[RefMatch]) -> bool {
    pem_blocks.iter().any(|b| pos >= b.start && pos < b.end)
}

/// Try every offset × every rule. Deliberately naive — oracle.
/// Skips positions inside PEM body regions (atomic suppression).
fn find_all_matches(input: &[u8], pem_blocks: &[RefMatch]) -> Vec<RefMatch> {
    let mut matches = Vec::new();
    for start in 0..input.len() {
        if is_in_pem_region(start, pem_blocks) {
            continue; // PEM body is atomic — no other rules run here
        }
        // Full-span rules: confirm returns end offset.
        for (rule, confirm) in [
            (GITHUB, confirm_github as fn(&[u8], usize) -> Option<usize>),
            (GITLAB, confirm_gitlab),
            (NPM, confirm_npm),
            (AWS_ACCESS, confirm_aws_access),
            (GCP_API, confirm_gcp_api),
            (PYPI, confirm_pypi),
            (JWT, confirm_jwt_oracle),
            (CREDIT_CARD, confirm_credit_card_oracle),
            (PHONE_INTL, confirm_phone_oracle),
        ] {
            if let Some(end) = confirm(input, start) {
                matches.push(RefMatch { start, end, rule });
            }
        }
        // Context-keyed/backward-looking: confirm returns (redact_start, redact_end).
        // These functions validate their anchor internally, so calling at
        // every offset is safe — non-anchor positions return None immediately.
        for (rule, confirm) in [
            (
                AWS_SECRET,
                confirm_aws_secret as fn(&[u8], usize) -> Option<(usize, usize)>,
            ),
            (AZURE, confirm_azure),
            (CONN_STRING, confirm_connstring),
            (EMAIL, confirm_email_oracle),
            (IPV6, confirm_ipv6_oracle),
        ] {
            if let Some((rs, re)) = confirm(input, start) {
                matches.push(RefMatch {
                    start: rs,
                    end: re,
                    rule,
                });
            }
        }
        // IPv4: only call at digit-dot positions to avoid duplicates from
        // backward-looking (the same IP found from multiple interior dots).
        if start + 1 < input.len()
            && input[start].is_ascii_digit()
            && input[start + 1] == b'.'
            && let Some((rs, re)) = confirm_ipv4_oracle(input, start)
        {
            matches.push(RefMatch {
                start: rs,
                end: re,
                rule: IPV4,
            });
        }
    }
    // Deduplicate: backward-looking rules may produce the same span from
    // multiple start positions (e.g., IPv4 from each digit-dot pair).
    matches.sort_unstable_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then(b.end.cmp(&a.end))
            .then(a.rule.cmp(&b.rule))
    });
    matches.dedup();
    matches
}

/// Group-absorption merge: each match absorbs every existing group it
/// strictly overlaps (touching spans stay separate — docs/02-rules.md).
/// Structurally different from the engine's sorted sweep, on purpose.
///
/// Group coverage is always contiguous (strict-overlap chains), so a match
/// overlapping a group's span overlaps one of its members.
fn merge_matches(matches: &[RefMatch]) -> Vec<RefMatch> {
    let mut groups: Vec<Vec<RefMatch>> = Vec::new();
    for &m in matches {
        let mut absorbed = vec![m];
        let mut remaining = Vec::new();
        for group in groups.drain(..) {
            let group_start = group
                .iter()
                .map(|x| x.start)
                .min()
                .expect("group is never empty");
            let group_end = group
                .iter()
                .map(|x| x.end)
                .max()
                .expect("group is never empty");
            if m.start < group_end && group_start < m.end {
                absorbed.extend(group);
            } else {
                remaining.push(group);
            }
        }
        remaining.push(absorbed);
        groups = remaining;
    }

    let mut merged: Vec<RefMatch> = groups
        .iter()
        .map(|group| {
            let start = group
                .iter()
                .map(|x| x.start)
                .min()
                .expect("group is never empty");
            let end = group
                .iter()
                .map(|x| x.end)
                .max()
                .expect("group is never empty");
            // Winner: longest-leftmost over the ORIGINAL member spans —
            // leftmost start, then longer, then catalog order.
            let winner = group
                .iter()
                .min_by(|a, b| {
                    a.start
                        .cmp(&b.start)
                        .then(b.end.cmp(&a.end))
                        .then(a.rule.cmp(&b.rule))
                })
                .expect("group is never empty");
            RefMatch {
                start,
                end,
                rule: winner.rule,
            }
        })
        .collect();
    merged.sort_unstable_by_key(|m| m.start);
    merged
}

/// Redact `input` as one whole buffer. Returns the redacted bytes and stats.
pub fn redact(input: &[u8], digest_key: &[u8; 32]) -> (Vec<u8>, Stats) {
    // 1. Find PEM blocks first (they suppress regular rules inside them).
    let pem_blocks = find_pem_blocks(input);
    // 2. Find regular matches, skipping PEM body regions.
    let mut all_matches = find_all_matches(input, &pem_blocks);
    // 3. Add PEM body spans to the match set.
    all_matches.extend_from_slice(&pem_blocks);
    let merged = merge_matches(&all_matches);

    let mut out = Vec::new();
    let mut match_counts: BTreeMap<RuleId, u64> = BTreeMap::new();
    let mut pos = 0;
    for m in &merged {
        out.extend_from_slice(&input[pos..m.start]);
        let rule_id = RuleId::new(RULE_IDS[m.rule]);
        let digest = crate::redact::compute_digest(&input[m.start..m.end], digest_key);
        crate::redact::write_tag(&rule_id, &digest, &mut out).expect("write to Vec cannot fail");
        *match_counts.entry(rule_id).or_insert(0) += 1;
        pos = m.end;
    }
    out.extend_from_slice(&input[pos..]);

    (
        out,
        Stats {
            bytes_processed: input.len() as u64,
            matches: match_counts,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{CATALOG, vectors};

    fn test_key() -> [u8; 32] {
        blake3::derive_key("cloak digest key", b"reference-test-key")
    }

    #[test]
    fn constants_cross_check_catalog() {
        // The oracle re-declares rule constants on purpose; this test is the
        // tripwire for drift between the two declarations.
        // Last RULE_ID is PEM (separate layer, not in CATALOG).
        assert_eq!(RULE_IDS.len(), CATALOG.len() + 1);
        for (idx, rule) in CATALOG.iter().enumerate() {
            assert_eq!(
                RULE_IDS[idx], rule.id,
                "oracle RULE_IDS[{idx}] = {:?} but CATALOG[{idx}].id = {:?}",
                RULE_IDS[idx], rule.id
            );
        }
        assert_eq!(RULE_IDS[PEM], crate::engine::pem::PEM_RULE_ID);
        // Spot-check simple-prefix anchors.
        let github_anchors: Vec<&[u8]> = GITHUB_PREFIXES.to_vec();
        assert_eq!(github_anchors, CATALOG[GITHUB].anchors);
        let gitlab_anchors: Vec<&[u8]> = GITLAB_PREFIXES.to_vec();
        assert_eq!(gitlab_anchors, CATALOG[GITLAB].anchors);
        assert_eq!(vec![NPM_PREFIX], CATALOG[NPM].anchors);
        let aws_anchors: Vec<&[u8]> = AWS_PREFIXES.to_vec();
        assert_eq!(aws_anchors, CATALOG[AWS_ACCESS].anchors);
        assert_eq!(vec![GCP_PREFIX], CATALOG[GCP_API].anchors);
        assert_eq!(vec![PYPI_PREFIX], CATALOG[PYPI].anchors);
        // PEM constants cross-check.
        assert_eq!(PEM_BEGIN, crate::engine::pem::PEM_ANCHOR);
        assert_eq!(PEM_BAIL_OUT, crate::engine::pem::PEM_BAIL_OUT);
        assert_eq!(PEM_KEY_TYPES.len(), crate::engine::pem::PEM_KEY_TYPES.len());
        for (oracle, engine) in PEM_KEY_TYPES.iter().zip(crate::engine::pem::PEM_KEY_TYPES) {
            assert_eq!(oracle, engine);
        }
    }

    // --- CRC32 oracle cross-check -------------------------------------------

    #[test]
    fn crc32_oracle_matches_crc32fast() {
        // Verify the hand-rolled oracle produces identical results to the
        // crc32fast crate used by the production engine — validates the
        // oracle without sharing code in the hot path.
        let test_inputs: &[&[u8]] = &[
            b"",
            b"x",
            b"AbCdEfGhIjKlMnOpQrStUvWxYz0123",
            b"aB1cD2eF3gH4iJ5kL6mN7oP8qR9sTu",
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123",
            b"0123456789abcdefghijklmnopqrst",
            &[0u8; 256],
            &(0..=255).collect::<Vec<u8>>(),
        ];
        for input in test_inputs {
            assert_eq!(
                crc32_oracle(input),
                crc32fast::hash(input),
                "CRC32 mismatch for input len {}",
                input.len()
            );
        }
    }

    #[test]
    fn base62_decode_6_oracle_known_values() {
        assert_eq!(base62_decode_6_oracle(b"000000"), Some(0));
        assert_eq!(base62_decode_6_oracle(b"000001"), Some(1));
        assert_eq!(base62_decode_6_oracle(b"2piBxe"), Some(0x9AC1C92E));
        assert_eq!(base62_decode_6_oracle(b"00000_"), None); // underscore
    }

    #[test]
    fn base62_decode_6_oracle_overflow() {
        // "zzzzzz" = 56_800_235_583 > u32::MAX → None.
        assert_eq!(base62_decode_6_oracle(b"zzzzzz"), None);
    }

    #[test]
    fn base62_decode_6_oracle_wrong_length() {
        assert_eq!(base62_decode_6_oracle(b"12345"), None); // 5 chars
        assert_eq!(base62_decode_6_oracle(b"1234567"), None); // 7 chars
    }

    #[test]
    fn crc32_oracle_standard_test_vector() {
        // CRC32 of "123456789" is the ISO-HDLC standard check value 0xCBF43926.
        assert_eq!(crc32_oracle(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn crc32_oracle_empty_input() {
        // CRC32 of empty input = 0x00000000.
        assert_eq!(crc32_oracle(b""), 0x00000000);
    }

    // --- confirmers -------------------------------------------------------

    #[test]
    fn github_classic_valid_crc() {
        // CRC32("AbCdEfGhIjKlMnOpQrStUvWxYz0123") → "2piBxe"
        let hit = b"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";
        assert_eq!(confirm_github(hit, 0), Some(40));
    }

    #[test]
    fn github_classic_wrong_crc_rejects() {
        let miss = b"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz01232piBxf";
        assert_eq!(confirm_github(miss, 0), None);
    }

    #[test]
    fn github_classic_exact_36_not_greedy() {
        // Valid CRC + extra chars: match is exactly prefix+36.
        let input = b"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Extra";
        assert_eq!(confirm_github(input, 0), Some(40));
    }

    #[test]
    fn github_classic_body_too_short() {
        let miss = b"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345678";
        assert_eq!(confirm_github(miss, 0), None);
    }

    #[test]
    fn github_classic_random_body_rejects() {
        // Shape matches but CRC doesn't validate — FP reduction.
        let input = b"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        assert_eq!(confirm_github(input, 0), None);
    }

    #[test]
    fn github_classic_underscore_rejects() {
        // Underscore not in base62 — rejected before CRC check.
        let input = b"ghp_AbCdEfGhIjKlMnOp_rStUvWxYz01232piBxe";
        assert_eq!(confirm_github(input, 0), None);
    }

    #[test]
    fn github_pat_shape_only() {
        let mut input = b"github_pat_".to_vec();
        input.extend(std::iter::repeat_n(b'x', 82));
        assert_eq!(confirm_github(&input, 0), Some(93));
    }

    #[test]
    fn github_pat_greedy_capped() {
        let mut input = b"github_pat_".to_vec();
        input.extend(std::iter::repeat_n(b'a', 300));
        assert_eq!(confirm_github(&input, 0), Some(266));
    }

    #[test]
    fn github_wrong_offset_and_prefix() {
        let input = b"xx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";
        assert_eq!(confirm_github(input, 0), None);
        assert_eq!(confirm_github(input, 2), Some(42));
    }

    #[test]
    fn github_charset_break() {
        let input = b"ghp_abcdefghij0123456789-abcdefghij0123456789";
        assert_eq!(confirm_github(input, 0), None);
    }

    #[test]
    fn gitlab_min_dash_body_and_below() {
        assert_eq!(confirm_gitlab(b"glpat-abcdefghij0123456789", 0), Some(26));
        assert_eq!(confirm_gitlab(b"glrt-abcdefghij0123456789", 0), Some(25));
        assert_eq!(confirm_gitlab(b"gldt-abcdefghij0123456789", 0), Some(25));
        assert_eq!(
            confirm_gitlab(b"glpat-ab-cd_ef-gh_ij-kl_mn-qrs", 0),
            Some(30)
        );
        assert_eq!(confirm_gitlab(b"glpat-abcdefghij012345678", 0), None);
    }

    #[test]
    fn gitlab_cap_at_255() {
        let mut input = b"glpat-".to_vec();
        input.extend(std::iter::repeat_n(b'z', 300));
        assert_eq!(confirm_gitlab(&input, 0), Some(261));
    }

    #[test]
    fn npm_valid_crc() {
        // CRC32("AbCdEfGhIjKlMnOpQrStUvWxYz0123") → "2piBxe"
        assert_eq!(
            confirm_npm(b"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", 0),
            Some(40)
        );
    }

    #[test]
    fn npm_valid_crc_with_trailing() {
        // Valid CRC + extra char: match is exactly prefix+36.
        assert_eq!(
            confirm_npm(b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz01232piBxeX", 0),
            Some(40)
        );
    }

    #[test]
    fn npm_wrong_crc_rejects() {
        assert_eq!(
            confirm_npm(b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz01232piBxf", 0),
            None
        );
    }

    #[test]
    fn npm_random_body_rejects() {
        // Shape matches but CRC doesn't validate.
        assert_eq!(
            confirm_npm(b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", 0),
            None
        );
    }

    #[test]
    fn npm_too_short() {
        assert_eq!(
            confirm_npm(b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz012345678", 0),
            None
        );
    }

    #[test]
    fn npm_underscore_rejects() {
        assert_eq!(
            confirm_npm(b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz012345678_", 0),
            None
        );
    }

    #[test]
    fn npm_wrong_prefix() {
        assert_eq!(
            confirm_npm(b"xpm_AbCdEfGhIjKlMnOpQrStUvWxYz01232piBxe", 0),
            None
        );
    }

    // --- merge ------------------------------------------------------------

    #[test]
    fn merge_empty_and_single() {
        assert!(merge_matches(&[]).is_empty());
        let single = [RefMatch {
            start: 5,
            end: 10,
            rule: NPM,
        }];
        assert_eq!(merge_matches(&single), single);
    }

    #[test]
    fn merge_disjoint_stays_sorted() {
        let matches = [
            RefMatch {
                start: 20,
                end: 30,
                rule: GITLAB,
            },
            RefMatch {
                start: 0,
                end: 10,
                rule: GITHUB,
            },
        ];
        let merged = merge_matches(&matches);
        assert_eq!(
            merged,
            [
                RefMatch {
                    start: 0,
                    end: 10,
                    rule: GITHUB
                },
                RefMatch {
                    start: 20,
                    end: 30,
                    rule: GITLAB
                },
            ]
        );
    }

    #[test]
    fn merge_touching_stays_separate() {
        // Strict overlap only: [0,10) + [10,20) do NOT merge.
        let matches = [
            RefMatch {
                start: 0,
                end: 10,
                rule: NPM,
            },
            RefMatch {
                start: 10,
                end: 20,
                rule: GITLAB,
            },
        ];
        assert_eq!(merge_matches(&matches), matches);
    }

    #[test]
    fn merge_overlap_leftmost_wins() {
        let matches = [
            RefMatch {
                start: 5,
                end: 25,
                rule: GITLAB,
            },
            RefMatch {
                start: 0,
                end: 10,
                rule: NPM,
            },
        ];
        assert_eq!(
            merge_matches(&matches),
            [RefMatch {
                start: 0,
                end: 25,
                rule: NPM
            }]
        );
    }

    #[test]
    fn merge_transitive_chain() {
        // A∩B and B∩C but A∌C → one span.
        let matches = [
            RefMatch {
                start: 0,
                end: 10,
                rule: GITHUB,
            },
            RefMatch {
                start: 18,
                end: 30,
                rule: NPM,
            },
            RefMatch {
                start: 8,
                end: 20,
                rule: GITLAB,
            },
        ];
        assert_eq!(
            merge_matches(&matches),
            [RefMatch {
                start: 0,
                end: 30,
                rule: GITHUB
            }]
        );
    }

    #[test]
    fn merge_same_start_longer_wins() {
        let matches = [
            RefMatch {
                start: 0,
                end: 10,
                rule: GITHUB,
            },
            RefMatch {
                start: 0,
                end: 20,
                rule: NPM,
            },
        ];
        assert_eq!(
            merge_matches(&matches),
            [RefMatch {
                start: 0,
                end: 20,
                rule: NPM
            }]
        );
    }

    #[test]
    fn merge_identical_span_catalog_order_wins() {
        let matches = [
            RefMatch {
                start: 0,
                end: 20,
                rule: NPM,
            },
            RefMatch {
                start: 0,
                end: 20,
                rule: GITLAB,
            },
        ];
        assert_eq!(
            merge_matches(&matches),
            [RefMatch {
                start: 0,
                end: 20,
                rule: GITLAB
            }]
        );
    }

    #[test]
    fn merge_contained_outer_wins() {
        let matches = [
            RefMatch {
                start: 5,
                end: 15,
                rule: NPM,
            },
            RefMatch {
                start: 0,
                end: 30,
                rule: GITHUB,
            },
        ];
        assert_eq!(
            merge_matches(&matches),
            [RefMatch {
                start: 0,
                end: 30,
                rule: GITHUB
            }]
        );
    }

    // --- redact (oracle vs. vector corpus) --------------------------------

    #[test]
    fn oracle_agrees_with_every_vector() {
        // The S2 checkpoint: reference green on the whole corpus before the
        // production engine exists.
        let key = test_key();
        for v in vectors::all_vectors() {
            let (out, stats) = redact(v.input, &key);
            assert_eq!(
                out,
                vectors::expected_output(v, &key),
                "oracle output mismatch on vector {}",
                v.name
            );
            assert_eq!(stats.bytes_processed, v.input.len() as u64, "{}", v.name);
            assert_eq!(stats.total_matches(), v.spans.len() as u64, "{}", v.name);
        }
    }

    #[test]
    fn redact_no_match_is_identity() {
        let key = test_key();
        let input: Vec<u8> = (0..=255).collect();
        let (out, stats) = redact(&input, &key);
        assert_eq!(out, input);
        assert_eq!(stats.bytes_processed, 256);
        assert!(stats.matches.is_empty());
    }

    #[test]
    fn redact_counts_per_rule() {
        let key = test_key();
        // npm with valid CRC + gitlab token.
        let input = b"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 glpat-abcdefghij0123456789";
        let (_, stats) = redact(input, &key);
        assert_eq!(stats.matches[&RuleId::new("npm-token")], 1);
        assert_eq!(stats.matches[&RuleId::new("gitlab-token")], 1);
    }
}
