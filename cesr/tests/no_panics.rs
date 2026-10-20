//! Parsers must reject malformed input with an error, never panic. Inputs
//! are random text, text from the CESR alphabet, and test
//! vectors that are truncated or mutated.

use std::{fs, path::Path, str::FromStr};

use cesrox::{
    conversion::{b64_to_num, from_text_to_bytes},
    derivation_code::DerivationCode,
    group::{codes::GroupCode, parse_group},
    parse, parse_value,
    payload::parse_payload,
    primitives::{
        codes::{
            attached_signature_code::AttachedSignatureCode, basic::Basic, seed::SeedCode,
            self_addressing::SelfAddressing, self_signing::SelfSigning, PrimitiveCode, TagCode,
        },
        parse_primitive,
    },
    values,
};
use proptest::prelude::*;

/// Runs every public parser on `input`; re-encodes whatever parses.
fn parse_everything(input: &[u8]) {
    if let Ok((value, _)) = parse_value(input) {
        let _ = value.to_string();
    }
    if let Ok(values) = parse(input) {
        for value in values {
            let _ = value.to_string();
        }
    }
    for value in values(input).flatten() {
        let _ = value.to_string();
    }
    let _ = cesrox::parse_with(input, cesrox::Counting::Quadlets);
    #[cfg(feature = "legacy-v2beta")]
    if let Ok(values) = cesrox::parse_with(input, cesrox::Counting::LegacyItems) {
        for value in values {
            let _ = value.to_string();
            if let cesrox::Value::SpecificGroup(group) = value {
                let _ = group.to_legacy_cesr_str();
            }
        }
    }
    if let Ok((group, _)) = parse_group(input) {
        let _ = group.to_cesr_str();
    }
    let _ = parse_payload(input);
    let _ = parse_primitive::<PrimitiveCode>(input);
    let _ = parse_primitive::<AttachedSignatureCode>(input).map(|(p, _)| p.code.to_str());
    let _ = parse_primitive::<Basic>(input);
    let _ = parse_primitive::<SelfAddressing>(input);
    let _ = parse_primitive::<SelfSigning>(input);
    let _ = parse_primitive::<SeedCode>(input);
    let _ = parse_primitive::<TagCode>(input);
    if let Ok(text) = std::str::from_utf8(input) {
        let _ = PrimitiveCode::from_str(text);
        let _ = TagCode::from_str(text);
        let _ = GroupCode::from_str(text);
        let _ = from_text_to_bytes(text);
        let _ = b64_to_num::<u64>(text);
    }
}

/// Text of every test vector of every source, as seeds for mutation.
fn corpus() -> Vec<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-vectors/v2");
    let sources: Vec<_> = fs::read_dir(&root)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    let mut out = vec![];
    for (dir, rel) in sources.iter().flat_map(|dir| {
        [
            "primitives/fixed.json",
            "primitives/variable.json",
            "primitives/special.json",
            "indexed/indexers.json",
            "counters/counters.json",
            "streams/messages.json",
        ]
        .map(|rel| (dir, rel))
    }) {
        let Ok(text) = fs::read_to_string(dir.join(rel)) else {
            continue;
        };
        let file: serde_json::Value = serde_json::from_str(&text).unwrap();
        for v in file["vectors"].as_array().into_iter().flatten() {
            for key in ["qb64", "stream"] {
                if let Some(s) = v[key].as_str() {
                    out.push(s.to_string());
                }
            }
        }
    }
    if out.is_empty() {
        out.push("-KABAACtbOtJRRB4ZpxAuXUbmFl5kJlvOg8bVWBSJcy-SKymfJbZpFZYwEDrQ1d8OW8kDbYQkCsc5JBz4gIq6kCtJrMN".into());
    }
    out
}

fn cesr_text() -> impl Strategy<Value = String> {
    "[-_A-Za-z0-9={}\"é]{0,120}"
}

fn mutated_vector() -> impl Strategy<Value = String> {
    let corpus = corpus();
    (
        prop::sample::select(corpus),
        any::<prop::sample::Index>(),
        any::<prop::sample::Index>(),
        prop::sample::select(vec!["", "A", "_", "-", "=", "9", "é", "{", "-_AAA"]),
    )
        .prop_map(|(seed, cut, at, insert)| {
            let chars: Vec<char> = seed.chars().collect();
            // keep a prefix, then splice a character in somewhere
            let prefix: Vec<char> = chars[..cut.index(chars.len() + 1)].to_vec();
            let pos = at.index(prefix.len() + 1);
            let mut out: String = prefix[..pos].iter().collect();
            out.push_str(insert);
            out.extend(&prefix[pos..]);
            out
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn any_bytes(input in any::<Vec<u8>>()) {
        parse_everything(&input);
    }

    #[test]
    fn any_text(input in any::<String>()) {
        parse_everything(input.as_bytes());
    }

    #[test]
    fn cesr_alphabet(input in cesr_text()) {
        parse_everything(input.as_bytes());
    }

    #[test]
    fn truncated_and_mutated_vectors(input in mutated_vector()) {
        parse_everything(input.as_bytes());
    }
}

#[test]
fn deeply_nested_groups_are_rejected() {
    // each level wraps the previous one in a generic group sized to fit it
    let mut stream = "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
    for _ in 0..4000 {
        let quadlets = stream.len() / 4;
        if quadlets > 4095 {
            break;
        }
        let count = cesrox::conversion::num_to_b64(quadlets as u16);
        stream = format!("-A{count:A>2}{stream}");
    }
    assert!(parse_value(stream.as_bytes()).is_err());
    assert!(parse(stream.as_bytes()).is_err());
}

#[test]
fn known_panics_are_errors() {
    for input in [
        "1",
        "1A",
        "1AA",
        "0",
        "X",
        "XA",
        "YAB",
        "2",
        "2A",
        "2AAB",
        "3B",
        "-KAB",
        "-KABA",
        "-KAB0",
        "-KAB2AA",
        "0é",
        "-KABé",
        "#",
        " ",
        "-NAB",
        "-RAB",
        "-UAB",
        "-VAB",
        "-WAB",
        "-XAB",
        "4ZAB",
        "7AAA",
        "0A====================AB",
        "0Jé",
        "0L_éAB",
        "1AAFé",
    ] {
        parse_everything(input.as_bytes());
        assert!(parse(input.as_bytes()).is_err(), "{input:?} parsed");
    }
    // a Bytes value that used to panic is valid V2
    assert!(parse(b"4BABEDVa").is_ok());
}
