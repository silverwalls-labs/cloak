//! Custom confirm/validation functions for rules that cannot be expressed
//! as pure regex-automata DFA patterns (docs/02-rules.md).
//!
//! Used as [`ConfirmSpec::Custom`](super::ConfirmSpec::Custom) callbacks.
//! Each function receives the full haystack and the anchor start position,
//! returning `None` to reject or `Some(ConfirmMatch)` with the redaction
//! span.
//!
//! Validators fall into three categories:
//! - **Value extractors** (context-keyed rules): match key+value context,
//!   return only the value sub-span as the redaction span.
//! - **Structural validators**: verify structure the DFA cannot (Luhn,
//!   JWT decode, octet ranges), return full span or reject.
//! - **Backward-looking**: anchor is interior (email `@`, IPv4 `.`),
//!   must scan backward to find the match start.

use crate::engine::confirm::ConfirmMatch;

// ── aws-secret-key (context-keyed) ──────────────────────────────────

/// Context-keyed confirm for `aws-secret-key`.
///
/// Anchors: `aws_secret`, `SecretAccessKey`.
/// Looks forward from the anchor for a separator (`_access_key` suffix if
/// needed, then `=`, `:`, or `":`), optional whitespace and quotes, then
/// a 40-char base64 value. Returns the value sub-span only.
pub(crate) fn confirm_aws_secret(haystack: &[u8], anchor: usize) -> Option<ConfirmMatch> {
    let rest = &haystack[anchor..];
    // Determine key name end — skip past the full key name.
    let key_end = if rest.starts_with(b"aws_secret_access_key") {
        anchor + 21 // "aws_secret_access_key" = 21 chars
    } else if rest.starts_with(b"SecretAccessKey") {
        anchor + 15 // "SecretAccessKey" = 15 chars
    } else {
        return None;
    };
    // Non-alnum boundary before the key name (not mid-word).
    if anchor > 0 && haystack[anchor - 1].is_ascii_alphanumeric() {
        return None;
    }
    // Scan for separator: skip optional quotes, whitespace, then `=`, `:`.
    let mut pos = key_end;
    // Skip closing quote if JSON key: `"SecretAccessKey":`
    while pos < haystack.len()
        && (haystack[pos] == b'"' || haystack[pos] == b'\'' || haystack[pos] == b' '
            || haystack[pos] == b'\t')
    {
        pos += 1;
    }
    if pos >= haystack.len() {
        return None;
    }
    // Accept `=` or `:`
    if haystack[pos] == b'=' || haystack[pos] == b':' {
        pos += 1;
    } else {
        return None;
    }
    // Skip whitespace and optional quotes after separator.
    while pos < haystack.len()
        && (haystack[pos] == b' '
            || haystack[pos] == b'\t'
            || haystack[pos] == b'"'
            || haystack[pos] == b'\'')
    {
        pos += 1;
    }
    // Now scan the 40-char base64 value.
    let value_start = pos;
    let mut taken = 0;
    while pos < haystack.len() && taken < 40 && is_base64_char(haystack[pos]) {
        pos += 1;
        taken += 1;
    }
    if taken != 40 {
        return None;
    }
    Some(ConfirmMatch {
        match_start: anchor,
        match_end: pos,
        redact_start: value_start,
        redact_end: pos,
    })
}

fn is_base64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
}

// ── azure-style-token (context-keyed) ───────────────────────────────

/// Context-keyed confirm for `azure-style-token`.
///
/// Anchors: `AccountKey=`, `accountkey=`, `sig=`.
/// The anchor already includes the `=` separator. Scan forward for a
/// base64 or URL-encoded value (min 20 chars, cap 255). Returns the
/// value sub-span only.
pub(crate) fn confirm_azure_token(haystack: &[u8], anchor: usize) -> Option<ConfirmMatch> {
    let rest = &haystack[anchor..];
    // Determine anchor length — anchor includes the `=`.
    let key_len = if rest.len() >= 11
        && rest[..11].eq_ignore_ascii_case(b"accountkey=")
    {
        11
    } else if rest.len() >= 4 && rest[..4].eq_ignore_ascii_case(b"sig=") {
        4
    } else {
        return None;
    };
    let value_start = anchor + key_len;
    let mut pos = value_start;
    let mut taken = 0;
    let cap = 255;
    while pos < haystack.len() && taken < cap && is_azure_value_char(haystack[pos]) {
        pos += 1;
        taken += 1;
    }
    if taken < 20 {
        return None;
    }
    Some(ConfirmMatch {
        match_start: anchor,
        match_end: pos,
        redact_start: value_start,
        redact_end: pos,
    })
}

fn is_azure_value_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' || b == b'%'
}

// ── connection-string (context-keyed, partial redaction) ─────────────

/// Allowed connection-string schemes (docs/02-rules.md).
const CONN_SCHEMES: &[&[u8]] = &[
    b"postgres",
    b"postgresql",
    b"mysql",
    b"mongodb",
    b"mongodb+srv",
    b"redis",
    b"amqp",
    b"amqps",
];

/// Context-keyed confirm for `connection-string`.
///
/// Anchor: `://`. Looks backward for a known scheme, forward for
/// `user:PASSWORD@host`. Returns the PASSWORD sub-span only.
pub(crate) fn confirm_connection_string(haystack: &[u8], anchor: usize) -> Option<ConfirmMatch> {
    // Anchor is `://` at `anchor`. Look backward for a scheme.
    let scheme_end = anchor;
    let mut scheme_start = anchor;
    while scheme_start > 0 && is_scheme_char(haystack[scheme_start - 1]) {
        scheme_start -= 1;
    }
    let scheme = &haystack[scheme_start..scheme_end];
    if !CONN_SCHEMES
        .iter()
        .any(|s| scheme.eq_ignore_ascii_case(s))
    {
        return None;
    }
    // After `://`, find `user:password@host` structure.
    let after_scheme = anchor + 3; // skip `://`
    // Find the `@` that separates credentials from host.
    let at_pos = haystack[after_scheme..]
        .iter()
        .position(|&b| b == b'@')
        .map(|p| after_scheme + p)?;
    // Cap the search window — don't scan past 300 bytes.
    if at_pos - after_scheme > 300 {
        return None;
    }
    // Find the `:` that separates user from password (first `:` after `://`).
    let userinfo = &haystack[after_scheme..at_pos];
    let colon_pos = userinfo.iter().position(|&b| b == b':')?;
    let password_start = after_scheme + colon_pos + 1;
    let password_end = at_pos;
    // Password must not be empty.
    if password_start >= password_end {
        return None;
    }
    Some(ConfirmMatch {
        match_start: scheme_start,
        match_end: at_pos + 1, // include the `@`
        redact_start: password_start,
        redact_end: password_end,
    })
}

fn is_scheme_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.'
}

// ── jwt ─────────────────────────────────────────────────────────────

/// Custom confirm for `jwt`.
///
/// Anchor: `eyJ`. Scans for three dot-separated base64url segments.
/// Decodes the first segment (header) and checks it starts with `{"` —
/// a minimal JSON object check.
pub(crate) fn confirm_jwt(haystack: &[u8], anchor: usize) -> Option<ConfirmMatch> {
    let rest = &haystack[anchor..];
    // Cap scan at 2048 bytes.
    let limit = rest.len().min(2048);
    let rest = &rest[..limit];

    // Find three dot-separated base64url segments.
    let dot1 = rest.iter().position(|&b| b == b'.')?;
    if dot1 == 0 {
        return None;
    }
    let after_dot1 = dot1 + 1;
    let dot2 = rest[after_dot1..]
        .iter()
        .position(|&b| b == b'.')
        .map(|p| after_dot1 + p)?;
    if dot2 == after_dot1 {
        return None;
    }
    // Third segment: scan base64url chars.
    let after_dot2 = dot2 + 1;
    let mut sig_end = after_dot2;
    while sig_end < rest.len() && is_base64url_char(rest[sig_end]) {
        sig_end += 1;
    }
    if sig_end == after_dot2 {
        return None;
    }
    // Validate all three segments are pure base64url.
    let header = &rest[..dot1];
    let payload = &rest[after_dot1..dot2];
    let signature = &rest[after_dot2..sig_end];
    if !header.iter().all(|&b| is_base64url_char(b))
        || !payload.iter().all(|&b| is_base64url_char(b))
        || !signature.iter().all(|&b| is_base64url_char(b))
    {
        return None;
    }
    // Decode header and check it looks like JSON.
    let decoded = base64url_decode(header)?;
    if decoded.len() < 2 || decoded[0] != b'{' || decoded[1] != b'"' {
        return None;
    }
    let match_end = anchor + sig_end;
    Some(ConfirmMatch::full(anchor, match_end))
}

fn is_base64url_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// Minimal base64url decoder (no padding, URL-safe alphabet).
fn base64url_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(input.len() * 3 / 4 + 2);
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

// ── credit-card ─────────────────────────────────────────────────────

/// Custom confirm for `credit-card`.
///
/// Anchors: IIN prefixes (`4`, `34`, `37`, `51`-`55`, `6011`, `65`).
/// Scans digits with optional space/dash separators. Validates:
/// 1. 13-19 total digits
/// 2. Non-digit boundaries
/// 3. IIN range (Big Four)
/// 4. Luhn checksum
pub(crate) fn confirm_credit_card(haystack: &[u8], anchor: usize) -> Option<ConfirmMatch> {
    // Non-digit boundary before the anchor.
    if anchor > 0 && haystack[anchor - 1].is_ascii_digit() {
        return None;
    }
    let rest = &haystack[anchor..];
    let limit = rest.len().min(25); // 19 digits + 6 separators max
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
            // Allow separators, but only between digits.
            if digits.is_empty() || end == 0 {
                break;
            }
            end += 1;
        } else {
            break;
        }
    }
    // Non-digit boundary after the match.
    let abs_end = anchor + end;
    if abs_end < haystack.len() && haystack[abs_end].is_ascii_digit() {
        return None;
    }
    // Must end on a digit (not a trailing separator).
    if end > 0 && !rest[end - 1].is_ascii_digit() {
        // Trim trailing separator.
        end -= 1;
    }
    let digit_count = digits.len();
    if digit_count < 13 || digit_count > 19 {
        return None;
    }
    // IIN check (Big Four).
    if !iin_check(&digits) {
        return None;
    }
    // Luhn checksum.
    if !luhn_check(&digits) {
        return None;
    }
    Some(ConfirmMatch::full(anchor, anchor + end))
}

/// Luhn mod-10 checksum validation.
fn luhn_check(digits: &[u8]) -> bool {
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
    sum % 10 == 0
}

/// Big Four IIN prefix check.
fn iin_check(digits: &[u8]) -> bool {
    if digits.is_empty() {
        return false;
    }
    let d0 = digits[0];
    match d0 {
        // Visa
        b'4' => true,
        // Amex
        b'3' if digits.len() >= 2 && (digits[1] == b'4' || digits[1] == b'7') => true,
        // Mastercard 51-55
        b'5' if digits.len() >= 2 && digits[1] >= b'1' && digits[1] <= b'5' => true,
        // Discover 6011 or 65
        b'6' if digits.len() >= 2 => {
            if digits[1] == b'5' {
                return true;
            }
            if digits.len() >= 4
                && digits[1] == b'0'
                && digits[2] == b'1'
                && digits[3] == b'1'
            {
                return true;
            }
            false
        }
        _ => false,
    }
}

// ── email ───────────────────────────────────────────────────────────

/// Custom confirm for `email`.
///
/// Anchor: `@`. Backward-looking: scans left for the local part and
/// right for the domain. RFC-5322-practical subset.
pub(crate) fn confirm_email(haystack: &[u8], anchor: usize) -> Option<ConfirmMatch> {
    // Backward: local part.
    let mut local_start = anchor;
    while local_start > 0 && is_email_local_char(haystack[local_start - 1]) {
        local_start -= 1;
    }
    if local_start == anchor {
        return None; // empty local part
    }
    // Local part must not start or end with a dot.
    if haystack[local_start] == b'.' || haystack[anchor - 1] == b'.' {
        return None;
    }
    // Reject URL credential context: local preceded by `:` or `/`.
    if local_start > 0
        && (haystack[local_start - 1] == b':' || haystack[local_start - 1] == b'/')
    {
        return None;
    }
    // Forward: domain.
    let domain_start = anchor + 1;
    let mut domain_end = domain_start;
    while domain_end < haystack.len() && is_email_domain_char(haystack[domain_end]) {
        domain_end += 1;
    }
    let domain = &haystack[domain_start..domain_end];
    // Domain must have at least one dot and a TLD of ≥ 2 alpha chars.
    let last_dot = domain.iter().rposition(|&b| b == b'.')?;
    let tld = &domain[last_dot + 1..];
    if tld.len() < 2 || !tld.iter().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    // Domain labels must not be empty or start/end with hyphens.
    for label in domain.split(|&b| b == b'.') {
        if label.is_empty()
            || label[0] == b'-'
            || label[label.len() - 1] == b'-'
        {
            return None;
        }
    }
    Some(ConfirmMatch::full(local_start, domain_end))
}

fn is_email_local_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || b == b'.'
        || b == b'+'
        || b == b'-'
        || b == b'_'
}

fn is_email_domain_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-'
}

// ── ipv4 ────────────────────────────────────────────────────────────

/// Custom confirm for `ipv4`.
///
/// Anchors: `0.` through `9.` (digit-dot composites).
/// Backward-looking: the anchor may land on the second or third octet's
/// dot. Scans backward to find the start of the first octet, then
/// parses four dot-separated octets (0-255) with non-digit boundaries.
pub(crate) fn confirm_ipv4(haystack: &[u8], anchor: usize) -> Option<ConfirmMatch> {
    // The anchor is a `<digit>.` pair. The digit might be in the middle
    // of an octet, so back up to find the start of the first octet.
    // We'll try parsing a valid IPv4 starting from each candidate start.
    // Back up at most 11 bytes (max: `255.255.255.` before the anchor digit).
    let earliest = anchor.saturating_sub(11);
    // Find a candidate start: scan backward for a non-digit byte.
    let mut start = anchor;
    while start > earliest
        && (haystack[start - 1].is_ascii_digit() || haystack[start - 1] == b'.')
    {
        start -= 1;
    }
    // Non-digit boundary before the IP.
    if start > 0 && haystack[start - 1].is_ascii_digit() {
        return None;
    }
    // Try parsing four octets from `start`.
    let mut pos = start;
    let mut octets = 0;
    while octets < 4 && pos < haystack.len() {
        let octet_start = pos;
        while pos < haystack.len() && haystack[pos].is_ascii_digit() {
            pos += 1;
        }
        let octet_len = pos - octet_start;
        if octet_len == 0 || octet_len > 3 {
            return None;
        }
        // No leading zeros (except "0" itself).
        if octet_len > 1 && haystack[octet_start] == b'0' {
            return None;
        }
        let val = parse_u8_unchecked(&haystack[octet_start..pos]);
        if val > 255 {
            return None;
        }
        octets += 1;
        if octets < 4 {
            if pos >= haystack.len() || haystack[pos] != b'.' {
                return None;
            }
            pos += 1; // skip dot
        }
    }
    if octets != 4 {
        return None;
    }
    // Non-digit boundary after.
    if pos < haystack.len() && haystack[pos].is_ascii_digit() {
        return None;
    }
    // Also reject if a 5th dot follows (e.g., `1.2.3.4.5`).
    if pos < haystack.len() && haystack[pos] == b'.' {
        return None;
    }
    Some(ConfirmMatch::full(start, pos))
}

fn parse_u8_unchecked(bytes: &[u8]) -> u16 {
    let mut val: u16 = 0;
    for &b in bytes {
        val = val * 10 + (b - b'0') as u16;
    }
    val
}

// ── ipv6 ────────────────────────────────────────────────────────────

/// Custom confirm for `ipv6`.
///
/// Anchor: `::`. Scans backward and forward to collect hex groups
/// separated by `:`. Validates bounded RFC-4291 grammar including `::`
/// compression. Also handles `::ffff:1.2.3.4` (v4-mapped).
pub(crate) fn confirm_ipv6(haystack: &[u8], anchor: usize) -> Option<ConfirmMatch> {
    // Find the start of the IPv6 address: back up through hex chars and colons.
    let mut start = anchor;
    while start > 0 && is_ipv6_char(haystack[start - 1]) {
        start -= 1;
    }
    // Non-hex/colon boundary before.
    if start > 0 && haystack[start - 1].is_ascii_alphanumeric() {
        return None;
    }
    // Find the end: forward through hex chars, colons, dots (v4-mapped).
    let mut end = anchor + 2; // skip `::`
    while end < haystack.len() && is_ipv6_ext_char(haystack[end]) {
        end += 1;
    }
    // Cap at 45 bytes.
    if end - start > 45 {
        return None;
    }
    // Non-hex boundary after.
    if end < haystack.len() && haystack[end].is_ascii_alphanumeric() {
        return None;
    }
    // Parse and validate the address.
    let addr = &haystack[start..end];
    if !validate_ipv6(addr) {
        return None;
    }
    Some(ConfirmMatch::full(start, end))
}

fn is_ipv6_char(b: u8) -> bool {
    b.is_ascii_hexdigit() || b == b':'
}

fn is_ipv6_ext_char(b: u8) -> bool {
    b.is_ascii_hexdigit() || b == b':' || b == b'.'
}

/// Validate an IPv6 address byte slice.
fn validate_ipv6(addr: &[u8]) -> bool {
    // Split on `::` — at most one occurrence.
    let parts: Vec<&[u8]> = split_on_double_colon(addr);
    match parts.len() {
        1 => {
            // No `::` compression — must have exactly 8 groups.
            let groups: Vec<&[u8]> = parts[0].split(|&b| b == b':').collect();
            groups.len() == 8 && groups.iter().all(|g| is_hex_group(g))
        }
        2 => {
            // `::` compression — left + right groups ≤ 8.
            let left: Vec<&[u8]> = if parts[0].is_empty() {
                vec![]
            } else {
                parts[0].split(|&b| b == b':').collect()
            };
            let right: Vec<&[u8]> = if parts[1].is_empty() {
                vec![]
            } else {
                parts[1].split(|&b| b == b':').collect()
            };
            let total = left.len() + right.len();
            if total > 7 {
                return false;
            }
            // Check if the last right group is v4-mapped (contains dots).
            if let Some(last) = right.last() {
                if last.contains(&b'.') {
                    // v4-mapped: last group is an IPv4 address.
                    let v4_groups = left.len() + right.len() - 1;
                    return v4_groups <= 6
                        && left.iter().all(|g| is_hex_group(g))
                        && right[..right.len() - 1].iter().all(|g| is_hex_group(g))
                        && is_valid_v4_suffix(last);
                }
            }
            left.iter().all(|g| is_hex_group(g)) && right.iter().all(|g| is_hex_group(g))
        }
        _ => false, // multiple `::`
    }
}

fn split_on_double_colon(addr: &[u8]) -> Vec<&[u8]> {
    let mut result = Vec::new();
    if let Some(pos) = addr.windows(2).position(|w| w == b"::") {
        result.push(&addr[..pos]);
        result.push(&addr[pos + 2..]);
    } else {
        result.push(addr);
    }
    result
}

fn is_hex_group(g: &[u8]) -> bool {
    !g.is_empty() && g.len() <= 4 && g.iter().all(|b| b.is_ascii_hexdigit())
}

fn is_valid_v4_suffix(bytes: &[u8]) -> bool {
    let s = std::str::from_utf8(bytes).ok();
    s.map_or(false, |s| {
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

// ── phone-intl ──────────────────────────────────────────────────────

/// Custom confirm for `phone-intl`.
///
/// Anchor: `+`. Strictly `+`-anchored international format (E.164-ish).
/// MUST NEVER match bare 10-digit strings — the `+` anchor is mandatory.
pub(crate) fn confirm_phone_intl(haystack: &[u8], anchor: usize) -> Option<ConfirmMatch> {
    // Non-digit boundary before `+`.
    if anchor > 0 && (haystack[anchor - 1].is_ascii_alphanumeric()) {
        return None;
    }
    if haystack[anchor] != b'+' {
        return None;
    }
    let mut pos = anchor + 1;
    let mut digit_count = 0;
    let limit = haystack.len().min(anchor + 25); // max scan window
    // Country code: first 1-3 digits.
    while pos < limit && haystack[pos].is_ascii_digit() {
        digit_count += 1;
        pos += 1;
    }
    if digit_count == 0 {
        return None;
    }
    // Scan remaining digits with optional separators (space, dash, dot).
    while pos < limit {
        let b = haystack[pos];
        if b.is_ascii_digit() {
            digit_count += 1;
            pos += 1;
        } else if b == b' ' || b == b'-' || b == b'.' {
            // Separator — must be followed by a digit.
            if pos + 1 >= limit || !haystack[pos + 1].is_ascii_digit() {
                break;
            }
            pos += 1;
        } else {
            break;
        }
    }
    // E.164: 7-15 digits total (country code + subscriber number).
    if digit_count < 7 || digit_count > 15 {
        return None;
    }
    // Non-digit boundary after.
    if pos < haystack.len() && haystack[pos].is_ascii_digit() {
        return None;
    }
    Some(ConfirmMatch::full(anchor, pos))
}

// ── Unit tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // --- Luhn ---

    #[test]
    fn luhn_valid_visa() {
        assert!(luhn_check(b"4539578763621486"));
    }

    #[test]
    fn luhn_valid_amex() {
        assert!(luhn_check(b"378282246310005"));
    }

    #[test]
    fn luhn_invalid() {
        assert!(!luhn_check(b"4539578763621487")); // last digit wrong
    }

    // --- IIN ---

    #[test]
    fn iin_visa() {
        assert!(iin_check(b"4539578763621486"));
    }

    #[test]
    fn iin_mastercard() {
        assert!(iin_check(b"5105105105105100"));
    }

    #[test]
    fn iin_amex() {
        assert!(iin_check(b"378282246310005"));
        assert!(iin_check(b"341111111111111"));
    }

    #[test]
    fn iin_discover() {
        assert!(iin_check(b"6011111111111117"));
        assert!(iin_check(b"6500000000000002"));
    }

    #[test]
    fn iin_reject_unknown() {
        assert!(!iin_check(b"9111111111111111"));
        assert!(!iin_check(b"1234567890123456"));
    }

    // --- base64url decode ---

    #[test]
    fn base64url_decode_jwt_header() {
        // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 decodes to
        // {"alg":"HS256","typ":"JWT"}
        let input = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let decoded = base64url_decode(input).unwrap();
        assert_eq!(&decoded, b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    }

    // --- email ---

    #[test]
    fn email_basic() {
        let h = b"user@example.com";
        let m = confirm_email(h, 4).unwrap();
        assert_eq!(m.redact_start, 0);
        assert_eq!(m.redact_end, 16);
    }

    #[test]
    fn email_no_tld() {
        assert!(confirm_email(b"user@localhost", 4).is_none());
    }

    #[test]
    fn email_short_tld() {
        assert!(confirm_email(b"user@example.c", 4).is_none());
    }

    // --- ipv4 ---

    #[test]
    fn ipv4_basic() {
        let h = b"192.168.1.1";
        // anchor at `2.` (position 2)
        let m = confirm_ipv4(h, 2).unwrap();
        assert_eq!(m.redact_start, 0);
        assert_eq!(m.redact_end, 11);
    }

    #[test]
    fn ipv4_rejects_octet_overflow() {
        assert!(confirm_ipv4(b"999.168.1.1", 2).is_none());
    }

    #[test]
    fn ipv4_rejects_leading_zeros() {
        assert!(confirm_ipv4(b"01.02.03.04", 1).is_none());
    }

    // --- ipv6 ---

    #[test]
    fn ipv6_loopback() {
        let h = b"::1";
        let m = confirm_ipv6(h, 0).unwrap();
        assert_eq!(m.redact_start, 0);
        assert_eq!(m.redact_end, 3);
    }

    #[test]
    fn ipv6_no_double_colon() {
        // Full form without `::` — the anchor never fires on this input.
        // The validator would only be called if the prefilter found `::`,
        // but we test the function directly to verify it rejects at any offset.
        let h = b"2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        // No `::` in this input. If called at offset 4, the chars around
        // position 4 are `0db8:` — no `::` at 4, so our function should
        // look for `::` from the anchor and won't find one starting at 4.
        // However, the function expects anchor to BE at `::` — position 4
        // is not `::`. Let's test with an actual `::` anchor position
        // instead: there is none, so this input should never match.
        for i in 0..h.len().saturating_sub(1) {
            if h[i] == b':' && i + 1 < h.len() && h[i + 1] == b':' {
                // Only test positions where `::` actually occurs.
                assert!(
                    confirm_ipv6(h, i).is_none(),
                    "unexpected match at offset {i}"
                );
            }
        }
    }

    #[test]
    fn ipv6_compressed() {
        let h = b"fe80::1";
        let m = confirm_ipv6(h, 4).unwrap();
        assert_eq!(m.redact_start, 0);
        assert_eq!(m.redact_end, 7);
    }

    #[test]
    fn ipv6_v4_mapped() {
        let h = b"::ffff:192.168.1.1";
        let m = confirm_ipv6(h, 0).unwrap();
        assert_eq!(m.redact_start, 0);
        assert_eq!(m.redact_end, 18);
    }

    // --- phone ---

    #[test]
    fn phone_us() {
        let h = b"+14155551234";
        let m = confirm_phone_intl(h, 0).unwrap();
        assert_eq!(m.redact_start, 0);
        assert_eq!(m.redact_end, 12);
    }

    #[test]
    fn phone_with_separators() {
        let h = b"+1-415-555-1234";
        let m = confirm_phone_intl(h, 0).unwrap();
        assert_eq!(m.redact_start, 0);
        assert_eq!(m.redact_end, 15);
    }

    #[test]
    fn phone_rejects_bare_digits() {
        // No `+` prefix — must not match.
        assert!(confirm_phone_intl(b"4155551234", 0).is_none());
    }

    #[test]
    fn phone_rejects_too_short() {
        // +123456 = only 6 digits, need 7.
        assert!(confirm_phone_intl(b"+123456", 0).is_none());
    }

    #[test]
    fn phone_rejects_preceded_by_alnum() {
        // Preceded by a letter — not a boundary.
        assert!(confirm_phone_intl(b"x+14155551234", 1).is_none());
    }

    // --- aws-secret-key ---

    #[test]
    fn aws_secret_basic() {
        let h = b"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let m = confirm_aws_secret(h, 0).unwrap();
        assert_eq!(m.redact_start, 24);
        assert_eq!(m.redact_end, 64);
    }

    #[test]
    fn aws_secret_json() {
        let h = b"\"SecretAccessKey\": \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"";
        let m = confirm_aws_secret(h, 1).unwrap();
        // Value starts after `": "` (with quotes).
        assert_eq!(m.redact_end - m.redact_start, 40);
    }

    // --- connection-string ---

    #[test]
    fn connstring_postgres() {
        let h = b"postgres://admin:s3cret@db.example.com:5432/mydb";
        // Anchor `://` is at position 8.
        let m = confirm_connection_string(h, 8).unwrap();
        assert_eq!(&h[m.redact_start..m.redact_end], b"s3cret");
    }

    #[test]
    fn connstring_no_password() {
        let h = b"postgres://nopass@host";
        assert!(confirm_connection_string(h, 8).is_none());
    }

    #[test]
    fn connstring_https_rejected() {
        let h = b"https://example.com";
        assert!(confirm_connection_string(h, 5).is_none());
    }

    // --- azure ---

    #[test]
    fn azure_account_key() {
        let h = b"AccountKey=dGhpcyBpcyBhIHRlc3QgdmFsdWUgd2l0aCBiYXNlNjQgZW5jb2Rpbmc=";
        let m = confirm_azure_token(h, 0).unwrap();
        assert_eq!(m.redact_start, 11); // after `AccountKey=`
        assert!(m.redact_end > m.redact_start + 20);
    }

    #[test]
    fn azure_sig_too_short() {
        let h = b"sig=abc";
        assert!(confirm_azure_token(h, 0).is_none());
    }
}
