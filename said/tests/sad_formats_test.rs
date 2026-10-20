//! The SAD derive gives the same SAIDs and messages as `said::saidify`, which
//! is checked against the shared test vectors, in every format.
#![cfg(feature = "macros")]

mod two_versioned_types {
    // no imports: the derive must not rely on names in scope

    #[derive(said::sad::SAD, serde::Serialize, Clone)]
    #[version(protocol = "KERI", major = 2, minor = 0)]
    pub struct Event {
        pub text: String,
        pub n: u64,
        pub keys: Vec<String>,
        #[said]
        pub d: Option<said::SelfAddressingIdentifier>,
    }

    #[derive(said::sad::SAD, serde::Serialize, Clone)]
    #[version(protocol = "ACDC", major = 1, minor = 0)]
    pub struct Credential {
        #[said]
        pub d: Option<said::SelfAddressingIdentifier>,
        pub issuer: String,
    }
}

use said::{
    derivation::HashFunctionCode,
    sad::{SerializationFormats, SAD},
    version::Encode,
    Sad,
};
use two_versioned_types::{Credential, Event};

fn event() -> Event {
    Event {
        text: "Hello world".into(),
        n: 3,
        keys: vec!["DA".into(), "DB".into()],
        d: None,
    }
}

#[test]
fn derive_matches_saidify_in_every_format() {
    let code = HashFunctionCode::Blake3_256;
    for format in [
        SerializationFormats::JSON,
        SerializationFormats::CBOR,
        SerializationFormats::MGPK,
    ] {
        let mut event = event();
        event.compute_digest(&code, &format).unwrap();
        let message = event.encode(&code, &format).unwrap();

        // the same map, saidified directly
        let mut sad: Sad = serde_json::from_value(serde_json::json!({
            "v": "KERICAACAAJSONAAAA.",
            "text": "Hello world",
            "n": 3,
            "keys": ["DA", "DB"],
            "d": "",
        }))
        .unwrap();
        let (said, expected) = said::saidify(&mut sad, code.clone(), format, &["d"]).unwrap();

        assert_eq!(event.d, Some(said), "{format:?}");
        assert_eq!(message, expected, "{format:?}");
    }
}

#[test]
fn cbor_maps_have_a_definite_length() {
    let code = HashFunctionCode::Blake3_256;
    let mut event = event();
    event
        .compute_digest(&code, &SerializationFormats::CBOR)
        .unwrap();
    let message = event.encode(&code, &SerializationFormats::CBOR).unwrap();
    // 0xa5: a map of five entries, not 0xbf (indefinite length)
    assert_eq!(message[0], 0xa5);
}

#[test]
fn version_size_is_the_message_size() {
    let code = HashFunctionCode::SHA3_256;
    for format in [SerializationFormats::JSON, SerializationFormats::MGPK] {
        let mut credential = Credential {
            d: None,
            issuer: "EIssuer".into(),
        };
        credential.compute_digest(&code, &format).unwrap();
        let message = credential.encode(&code, &format).unwrap();
        let derivation = credential.derivation_data(&code, &format).unwrap();
        assert_eq!(message.len(), derivation.len());
        let text = String::from_utf8_lossy(&message);
        let size = format!("{:06x}_", message.len());
        assert!(text.contains(&size), "{format:?}: {text}");
    }
}

#[test]
fn native_cesr_is_reported_not_panicked() {
    let mut event = event();
    let code = HashFunctionCode::Blake3_256;
    assert!(event
        .compute_digest(&code, &SerializationFormats::CESR)
        .is_err());
}
