//! Parsing untrusted version strings, SAIDs and messages must fail with an
//! error, never panic.

use std::str::FromStr;

use proptest::prelude::*;
use said::{
    sad::SerializationFormats, verify, version::SerializationInfo, SelfAddressingIdentifier,
};

fn parse_everything(input: &str) {
    let _ = SerializationInfo::from_str(input);
    let _ = SelfAddressingIdentifier::from_str(input);
    let json = serde_json::Value::String(input.to_string()).to_string();
    let _ = serde_json::from_str::<SerializationInfo>(&json);
    let _ = serde_json::from_str::<SelfAddressingIdentifier>(&json);
}

fn verify_everything(message: &[u8]) {
    for format in [
        SerializationFormats::JSON,
        SerializationFormats::CBOR,
        SerializationFormats::MGPK,
    ] {
        let _ = verify(message, format, &["d"]);
        let _ = verify(message, format, &["i", "d"]);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn any_message(message in any::<Vec<u8>>()) {
        verify_everything(&message);
    }

    #[test]
    fn json_messages(
        v in "[-_A-Za-z0-9.é]{0,24}",
        d in "[-_A-Za-z0-9#]{0,90}",
        i in "[-_A-Za-z0-9#]{0,90}",
    ) {
        let message = serde_json::json!({"v": v, "i": i, "d": d}).to_string();
        verify_everything(message.as_bytes());
    }

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
