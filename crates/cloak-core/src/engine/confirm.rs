//! Confirm step: per-rule anchored dense DFA over candidate windows
//! (docs/01-architecture.md, "Matching pipeline").
//!
//! ## Pattern constraints (future rules MUST honor these)
//!
//! regex-automata 0.4 has no `MatchKind::LeftmostLongest`. We rely on
//! greedy-repetition + `LeftmostFirst` returning the LONGEST match at the
//! anchored start, which holds only when:
//! - alternation branches (the anchor prefixes) are mutually non-prefix
//!   (no branch is a prefix of another), and
//! - the body is a single greedy repetition of one byte class.
//!
//! Arbitrary alternations break this. The greedy-pin unit tests below are
//! the tripwire.

use regex_automata::dfa::{Automaton, StartKind, dense};
use regex_automata::util::syntax;
use regex_automata::{Anchored, Input, MatchKind};

use super::BuildError;
use crate::rules::RuleSpec;
use crate::types::RuleId;

/// One catalog rule compiled for matching.
pub(crate) struct CompiledRule {
    pub id: RuleId,
    /// Max match window `W` (bounds the candidate window; S3 carry-over).
    pub window: usize,
    dfa: dense::DFA<Vec<u32>>,
}

/// Compile one catalog spec. Split out of `Engine::new` so the error path is
/// unit-testable (the static catalog can never fail the happy path).
pub(crate) fn compile_rule(spec: &RuleSpec) -> Result<CompiledRule, BuildError> {
    let dfa = dense::Builder::new()
        .configure(
            dense::Config::new()
                // Only anchored start states: smaller DFA, and every search
                // passes Anchored::Yes.
                .start_kind(StartKind::Anchored)
                .match_kind(MatchKind::LeftmostFirst),
        )
        // Byte-oriented, never str: a token embedded in a binary blob is
        // still caught (docs/03).
        .syntax(syntax::Config::new().unicode(false).utf8(false))
        .build(spec.confirm_pattern)
        .map_err(|source| BuildError::Confirm {
            rule: RuleId::new(spec.id),
            source: Box::new(source),
        })?;
    Ok(CompiledRule {
        id: RuleId::new(spec.id),
        window: spec.window,
        dfa,
    })
}

/// Run the rule's anchored DFA over the candidate window starting at
/// `anchor_start`. Returns the absolute end offset of the longest-at-anchor
/// match, if any.
pub(crate) fn confirm(rule: &CompiledRule, haystack: &[u8], anchor_start: usize) -> Option<usize> {
    let window_end = anchor_start.saturating_add(rule.window).min(haystack.len());
    // Input::range keeps offsets haystack-absolute — no re-basing.
    let input = Input::new(haystack)
        .range(anchor_start..window_end)
        .anchored(Anchored::Yes);
    rule.dfa
        .try_search_fwd(&input)
        // Infallible for our DFAs: no quit bytes (pure ASCII patterns, no
        // look-around, unicode off) and anchored starts are compiled in.
        .expect("dense DFA with no quit bytes cannot fail")
        .map(|half| half.offset())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::CATALOG;

    fn compiled(rule: usize) -> CompiledRule {
        compile_rule(&CATALOG[rule]).expect("static catalog must compile")
    }

    #[test]
    fn github_min_confirms_and_below_rejects() {
        let rule = compiled(0);
        assert_eq!(
            confirm(&rule, b"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", 0),
            Some(40)
        );
        assert_eq!(
            confirm(&rule, b"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345678", 0),
            None
        );
    }

    #[test]
    fn greedy_pin_longest_at_anchor() {
        // THE load-bearing semantics test: LeftmostFirst + greedy {36,255}
        // must take all 40 body chars, not stop at the 36-char minimum.
        let rule = compiled(0);
        assert_eq!(
            confirm(&rule, b"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Wxyz", 0),
            Some(44)
        );
    }

    #[test]
    fn greedy_pin_cap_at_255() {
        let rule = compiled(0);
        let mut input = b"ghp_".to_vec();
        input.extend(std::iter::repeat_n(b'a', 255));
        assert_eq!(confirm(&rule, &input, 0), Some(259));
        // Over the cap: still 259, never more.
        input.extend(std::iter::repeat_n(b'a', 45));
        assert_eq!(confirm(&rule, &input, 0), Some(259));
    }

    #[test]
    fn charset_break_stops_the_match() {
        let rule = compiled(0);
        // 20 valid body chars, then '-' — below the 36 minimum.
        assert_eq!(
            confirm(&rule, b"ghp_abcdefghij0123456789-abcdefghij0123456789", 0),
            None
        );
    }

    #[test]
    fn github_pat_branch_confirms() {
        let rule = compiled(0);
        let mut input = b"github_pat_".to_vec();
        input.extend(std::iter::repeat_n(b'x', 82));
        assert_eq!(confirm(&rule, &input, 0), Some(93));
    }

    #[test]
    fn gitlab_charset_includes_dash_and_underscore() {
        let rule = compiled(1);
        assert_eq!(
            confirm(&rule, b"glpat-ab-cd_ef-gh_ij-kl_mn-qrs", 0),
            Some(30)
        );
        assert_eq!(confirm(&rule, b"glrt-abcdefghij0123456789", 0), Some(25));
        assert_eq!(confirm(&rule, b"glpat-abcdefghij012345678", 0), None);
    }

    #[test]
    fn npm_exactly_36_no_boundary_check() {
        let rule = compiled(2);
        assert_eq!(
            confirm(&rule, b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", 0),
            Some(40)
        );
        // 37 alnum: match ends at 40 (first 36) — spec-literal.
        assert_eq!(
            confirm(&rule, b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789X", 0),
            Some(40)
        );
        assert_eq!(
            confirm(&rule, b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz012345678", 0),
            None
        );
    }

    #[test]
    fn anchored_search_at_nonzero_offset() {
        let rule = compiled(2);
        let input = b"xx npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        assert_eq!(confirm(&rule, input, 3), Some(43));
        // Anchored: searching from 0 must NOT skip ahead to the token.
        assert_eq!(confirm(&rule, input, 0), None);
    }

    #[test]
    fn window_clamps_at_haystack_end() {
        let rule = compiled(0);
        // Anchor 3 bytes before EOF: window clamps, no match, no panic.
        assert_eq!(confirm(&rule, b"end ghp", 4), None);
        assert_eq!(confirm(&rule, b"ghp_", 0), None);
    }

    #[test]
    fn compile_error_surfaces_as_build_error() {
        let bad = RuleSpec {
            id: "synthetic-bad",
            anchors: &[b"x_"],
            confirm_pattern: "(", // unclosed group — cannot compile
            window: 10,
        };
        match compile_rule(&bad) {
            Err(BuildError::Confirm { rule, .. }) => {
                assert_eq!(rule.to_string(), "synthetic-bad");
            }
            Err(other) => panic!("expected BuildError::Confirm, got {other:?}"),
            Ok(_) => panic!("expected compile failure"),
        }
    }
}
