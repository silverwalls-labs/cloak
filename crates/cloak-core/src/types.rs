use std::collections::BTreeMap;
use std::fmt;

/// Stable identifier for a detection rule in the catalog.
///
/// Rule ids are stable from v0.1 — renaming is a breaking change.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
pub struct RuleId(String);

impl RuleId {
    /// Constructs a rule id. Catalog ids (e.g. `"aws-access-key"`) are canonical.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Truncated keyed BLAKE3 digest (16 bits = 4 hex chars).
///
/// Used for correlation — same secret + same key → same digest —
/// without exposing the matched plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Digest([u8; 2]);

impl Digest {
    /// Wraps 2 raw digest bytes, as produced by [`compute_digest`](crate::compute_digest).
    pub fn new(bytes: [u8; 2]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}{:02x}", self.0[0], self.0[1])
    }
}

/// Per-match event record.
///
/// Reserved for the v0.2 event-callback API (`docs/06-embedding.md`).
/// Not currently constructed by the engine — v0.1 reports matches
/// via aggregate [`Stats`] only.
///
/// Critically, this struct **never** carries the matched plaintext — the secret
/// must not escape through the reporting side-channel.
#[derive(Debug, Clone)]
pub struct MatchEvent {
    /// The rule that matched.
    pub rule: RuleId,
    /// Correlation digest of the matched bytes — never the plaintext itself.
    pub digest: Digest,
}

/// Per-stream statistics returned by [`Session::finish`](crate::Session::finish).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Stats {
    /// Total bytes pushed through the session.
    pub bytes_processed: u64,
    /// Per-rule match count (BTreeMap for deterministic iteration order).
    pub matches: BTreeMap<RuleId, u64>,
    /// Per-rule near-miss count: candidates that matched the rule's shape
    /// (prefix, body length, character class) but failed checksum or
    /// structural validation (CRC32, Luhn). A spike from zero signals
    /// upstream format drift — the checksum scheme changed and real tokens
    /// are passing through unredacted. Empty when no near-misses occurred;
    /// `skip_serializing_if` keeps existing JSON output byte-identical.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub near_misses: BTreeMap<RuleId, u64>,
}

impl Stats {
    /// Sum of all per-rule match counts.
    pub fn total_matches(&self) -> u64 {
        self.matches.values().sum()
    }

    /// Sum of all per-rule near-miss counts.
    pub fn total_near_misses(&self) -> u64 {
        self.near_misses.values().sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_id_display() {
        assert_eq!(RuleId::new("aws-access-key").to_string(), "aws-access-key");
    }

    #[test]
    fn digest_display() {
        assert_eq!(Digest::new([0x9f, 0x3a]).to_string(), "9f3a");
    }

    #[test]
    fn digest_display_leading_zero() {
        assert_eq!(Digest::new([0x0a, 0x01]).to_string(), "0a01");
    }

    #[test]
    fn stats_default_empty() {
        let stats = Stats::default();
        assert_eq!(stats.bytes_processed, 0);
        assert!(stats.matches.is_empty());
        assert_eq!(stats.total_matches(), 0);
    }

    #[test]
    fn stats_total_matches() {
        let mut stats = Stats::default();
        stats.matches.insert(RuleId::new("rule-a"), 3);
        stats.matches.insert(RuleId::new("rule-b"), 7);
        assert_eq!(stats.total_matches(), 10);
    }

    #[test]
    fn stats_near_misses_default_empty() {
        let stats = Stats::default();
        assert!(stats.near_misses.is_empty());
        assert_eq!(stats.total_near_misses(), 0);
    }

    #[test]
    fn stats_total_near_misses() {
        let mut stats = Stats::default();
        stats.near_misses.insert(RuleId::new("github-token"), 5);
        stats.near_misses.insert(RuleId::new("npm-token"), 3);
        assert_eq!(stats.total_near_misses(), 8);
    }

    #[test]
    fn stats_json_omits_empty_near_misses() {
        let stats = Stats::default();
        let json = serde_json::to_string(&stats).unwrap();
        assert!(
            !json.contains("near_misses"),
            "empty near_misses must be omitted from JSON: {json}"
        );
    }

    #[test]
    fn stats_json_includes_nonempty_near_misses() {
        let mut stats = Stats::default();
        stats.near_misses.insert(RuleId::new("github-token"), 1);
        let json = serde_json::to_string(&stats).unwrap();
        assert!(
            json.contains("near_misses"),
            "non-empty near_misses must appear in JSON: {json}"
        );
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["near_misses"]["github-token"], 1);
    }
}
