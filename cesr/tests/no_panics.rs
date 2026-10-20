//! Parsers must reject malformed input with an error, never panic. Inputs
//! are random text, text from the CESR alphabet, and keripy-generated
//! vectors that are truncated or mutated.

use std::{fs, path::Path, str::FromStr};

use cesrox::{
    conversion::{b64_to_num, from_text_to_bytes},
    derivation_code::DerivationCode,
    group::{codes::GroupCode, parsers::group_code},
    parse_all, parse_one,
    primitives::{
        codes::{
            attached_signature_code::AttachedSignatureCode, basic::Basic, seed::SeedCode,
            self_addressing::SelfAddressing, self_signing::SelfSigning, PrimitiveCode, TagCode,
        },
        parsers::{
            anchoring_event_seal, identifier, parse_primitive, serial_number_parser,
            timestamp_parser,
        },
    },
    universal_codes::{genus_code, short_universal_group_code},
};
use proptest::prelude::*;

/// Runs every public parser on `input`; re-encodes whatever parses.
fn parse_everything(input: &str) {
    if let Ok((_, value)) = parse_one(input) {
        let _ = value.to_string();
    }
    if let Ok((_, values)) = parse_all(input) {
        for value in values {
            let _ = value.to_string();
        }
    }
    if let Ok((_, code)) = group_code(input) {
        let _ = code.to_str();
    }
    let _ = genus_code(input);
    let _ = short_universal_group_code(input);
    let _ = parse_primitive::<PrimitiveCode>(input);
    let _ = parse_primitive::<AttachedSignatureCode>(input).map(|(_, (c, _))| c.to_str());
    let _ = parse_primitive::<Basic>(input);
    let _ = parse_primitive::<SelfAddressing>(input);
    let _ = parse_primitive::<SelfSigning>(input);
    let _ = parse_primitive::<SeedCode>(input);
    let _ = identifier(input);
    let _ = serial_number_parser(input);
    let _ = timestamp_parser(input);
    let _ = anchoring_event_seal(input);
    let _ = PrimitiveCode::from_str(input);
    let _ = TagCode::from_str(input);
    let _ = GroupCode::from_str(input);
    let _ = from_text_to_bytes(input);
    let _ = b64_to_num(input);
}

/// Text of every keripy vector, as seeds for mutation.
fn corpus() -> Vec<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-vectors/v2");
    let mut out = vec![];
    for rel in [
        "primitives/fixed.json",
        "primitives/variable.json",
        "primitives/special.json",
        "indexed/indexers.json",
        "counters/counters.json",
        "streams/messages.json",
    ] {
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
    fn any_text(input in any::<String>()) {
        parse_everything(&input);
    }

    #[test]
    fn cesr_alphabet(input in cesr_text()) {
        parse_everything(&input);
    }

    #[test]
    fn truncated_and_mutated_vectors(input in mutated_vector()) {
        parse_everything(&input);
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
        stream = format!(
            "-A{}{}",
            cesrox::conversion::adjust_with_num(quadlets as u16, 2),
            stream
        );
    }
    assert!(parse_one(&stream).is_err());
    assert!(parse_all(&stream).is_err());
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
        "4BABEDVa",
        "4ZAB",
        "7AAA",
        "0A====================AB",
    ] {
        parse_everything(input);
        assert!(
            parse_one(input)
                .map(|(rest, _)| !rest.is_empty())
                .unwrap_or(true),
            "{input:?} parsed completely"
        );
    }
}
