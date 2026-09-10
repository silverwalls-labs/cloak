use std::collections::BTreeMap;
use std::fmt;

/// Stable identifier for a detection rule in the catalog.
///
/// Rule ids are stable from v0.1 — renaming is a breaking change.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
pub struct RuleId(String);

impl RuleId {
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
    pub rule: RuleId,
    pub digest: Digest,
}

/// Per-stream statistics returned by [`Session::finish`](crate::Session::finish).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Stats {
    /// Total bytes pushed through the session.
    pub bytes_processed: u64,
    /// Per-rule match count (BTreeMap for deterministic iteration order).
    pub matches: BTreeMap<RuleId, u64>,
}

impl Stats {
    /// Sum of all per-rule match counts.
    pub fn total_matches(&self) -> u64 {
        self.matches.values().sum()
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
}
