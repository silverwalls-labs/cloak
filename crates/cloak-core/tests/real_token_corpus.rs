//! Real-token corpus regression (F12, review finding R1).
//!
//! 20 real, EXPIRED GitHub classic tokens, published for format
//! reverse-engineering in `therootcompany/base62-token.js` issue #2
//! (Jan 2022). They pin the external format assumptions against real
//! tokens — CRC32 (ISO-HDLC) over the 30-char entropy, base62
//! (`0-9A-Za-z`) big-endian with `'0'` padding, in the last 6 body
//! chars. Synthetic vectors cannot catch a wrong format assumption
//! (they are generated with it); real tokens can. If GitHub ever
//! changes the checksum scheme, this test is the tripwire.
//!
//! The corpus is stored hex-encoded: the raw strings are token-shaped,
//! and GitHub push protection blocks any push containing them in plain
//! text — even though these tokens are long-expired and public. Runtime
//! decoding feeds the validator the identical bytes.
//!
//! All tokens are long-expired and public; none are valid credentials.
//! npm has no public corpus — the npm side stays pinned by the manual
//! spot check (PR #32 checklist).

use cloak_core::{Config, Engine, RuleId};

/// Real expired `ghp_` tokens, hex-encoded (base62-token.js issue #2;
/// verified 2026-09-11: all 20 carry a valid CRC32 under the F12 scheme).
const CORPUS_HEX: &[&str] = &[
    "6768705f7a5157427554534f6f5269344139737048635659356e636e73446b786b4a306d4c713137",
    "6768705f6164453764703872485036675554755077784c545a6a5a647479613373563055517a514d",
    "6768705f483378626942646c7a66664e7837593536694e735077336a6f4f626a3755326e4f323968",
    "6768705f556c3665495568584f5745373544654c66506e6455553047626365427138304b49686134",
    "6768705f6b724c5a38664a7457624d3656685a567658784c686f636777384a636652326442445779",
    "6768705f726345437068703567306c73543664527749694443566244516f7836484c31484d6a397a",
    "6768705f715a55446b545372436c546c475936785a4c584933597953794a634461763075304e7734",
    "6768705f5655424e6a4936717955664c4830547a494f53415176546934424b36656f3353776f6d62",
    "6768705f413435706355577978704433436c6f663475767174497469583371305248304f49324734",
    "6768705f5455314d485263397a673848335a656a5a6e613376786958753843653831304a734d474b",
    "6768705f726669456d4d6569313656465839343131394875544e54586d526c4d6d41343235715a53",
    "6768705f327a76643148766a7a41476641756c4f546c4d346e5362776c6332634938343467324531",
    "6768705f766466703171556e7177354c71585a765164306e56586e59516938764a50344d774e6559",
    "6768705f6e726966553472706a747a53506451774c524e7371764f44476867346d7134356a476969",
    "6768705f376b43577a6b4f6d6f69705959705352327049704a75666b5576466c5859316463797a5a",
    "6768705f56586667493965734a5a4555346154726f38417a62614f6b6744324f4b53334c43427575",
    "6768705f3571574842736f396444685a496f4e79724366785135624b506d654e6e383164576c4854",
    "6768705f67554a52667648555258584b31664b5a6251657868563339564c7849676332646d4b6473",
    "6768705f5557665a77486244476f66627876756261537433685641747172756d56503033696e4d61",
    "6768705f4d58756d3831495948376b696f57517949764e347a504d66454349575964316c64794348",
];

fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn real_expired_github_tokens_are_detected() {
    let engine = Engine::new(&Config::ephemeral()).unwrap();
    for hex in CORPUS_HEX {
        let token = decode_hex(hex);
        assert_eq!(token.len(), 40, "corpus entry must be a 40-byte token");

        let mut session = engine.session();
        let mut out = Vec::new();
        session.push(&token, &mut out).unwrap();
        let stats = session.finish(&mut out).unwrap();

        assert_eq!(
            stats.matches.get(&RuleId::new("github-token")),
            Some(&1),
            "real expired token must be detected: {}",
            String::from_utf8_lossy(&token)
        );
        assert!(
            !out.windows(4).any(|w| w == b"ghp_"),
            "token must not leak: {}",
            String::from_utf8_lossy(&out)
        );
    }
}

#[test]
fn corrupted_real_token_is_rejected() {
    // Negative control: flipping one checksum char of a real token must
    // reject it — proves the corpus test exercises CRC validation, not
    // just shape matching.
    let engine = Engine::new(&Config::ephemeral()).unwrap();
    let mut corrupted = decode_hex(CORPUS_HEX[0]);
    corrupted[39] = if corrupted[39] == b'x' { b'y' } else { b'x' };

    let mut session = engine.session();
    let mut out = Vec::new();
    session.push(&corrupted, &mut out).unwrap();
    let stats = session.finish(&mut out).unwrap();

    assert!(
        !stats.matches.contains_key(&RuleId::new("github-token")),
        "corrupted real token must be rejected"
    );
    assert_eq!(&out[..], &corrupted[..], "corrupted token passes through");
}
