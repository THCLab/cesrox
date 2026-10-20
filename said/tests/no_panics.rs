//! Parsing untrusted version strings and SAIDs must fail with an error,
//! never panic.

use std::str::FromStr;

use proptest::prelude::*;
use said::{version::SerializationInfo, SelfAddressingIdentifier};

fn parse_everything(input: &str) {
    let _ = SerializationInfo::from_str(input);
    let _ = SelfAddressingIdentifier::from_str(input);
    let json = serde_json::Value::String(input.to_string()).to_string();
    let _ = serde_json::from_str::<SerializationInfo>(&json);
    let _ = serde_json::from_str::<SelfAddressingIdentifier>(&json);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn any_text(input in any::<String>()) {
        parse_everything(&input);
    }

    #[test]
    fn version_and_said_alphabet(input in "[-_A-Za-z0-9.é]{0,60}") {
        parse_everything(&input);
    }
}

#[test]
fn known_panics_are_errors() {
    for input in [
        "",
        "KERI",
        "KERI10JSON",
        "KERI10JSON00014",
        "KERIé0JSON00014b_",
        "0",
        "0é",
        "E",
    ] {
        parse_everything(input);
        assert!(SerializationInfo::from_str(input).is_err(), "{input:?}");
        assert!(
            SelfAddressingIdentifier::from_str(input).is_err(),
            "{input:?}"
        );
    }
}
