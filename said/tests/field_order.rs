//! A SAID covers the bytes of a message, so field order must be kept as
//! given at every depth. said must keep it by itself: it no longer turns on
//! serde_json's `preserve_order`, which would re-order the JSON of every
//! other crate built with it.

use said::{
    derivation::HashFunctionCode, sad::SerializationFormats, saidify, saidify_value, to_sad,
    verify, Sad, SelfAddressingIdentifier,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct Inner {
    y: u8,
    b: u8,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct Outer {
    d: Option<SelfAddressingIdentifier>,
    z: Inner,
    a: String,
}

const FORMATS: [SerializationFormats; 3] = [
    SerializationFormats::JSON,
    SerializationFormats::CBOR,
    SerializationFormats::MGPK,
];

#[test]
fn nested_fields_keep_their_order() {
    let mut outer = Outer {
        d: None,
        z: Inner { y: 1, b: 2 },
        a: "x".into(),
    };
    let (said, message) = saidify_value(
        &mut outer,
        HashFunctionCode::Blake3_256,
        SerializationFormats::JSON,
        &["d"],
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(message).unwrap(),
        format!(r#"{{"d":"{said}","z":{{"y":1,"b":2}},"a":"x"}}"#)
    );
}

#[test]
fn a_message_with_nested_fields_out_of_key_order_verifies() {
    for format in FORMATS {
        let mut outer = Outer {
            d: None,
            z: Inner { y: 1, b: 2 },
            a: "x".into(),
        };
        let (said, message) =
            saidify_value(&mut outer, HashFunctionCode::Blake3_256, format, &["d"]).unwrap();
        assert_eq!(
            verify(&message, format, &["d"]).unwrap(),
            said,
            "{format:?}"
        );
    }
}

#[test]
fn to_sad_keeps_the_order_of_the_serialization() {
    let sad = to_sad(&Outer {
        d: None,
        z: Inner { y: 1, b: 2 },
        a: "x".into(),
    })
    .unwrap();
    assert_eq!(sad.keys().collect::<Vec<_>>(), ["d", "z", "a"]);
    assert_eq!(
        serde_json::to_string(&sad["z"]).unwrap(),
        r#"{"y":1,"b":2}"#
    );
}

#[test]
fn a_sad_parsed_from_text_keeps_nested_order() {
    let mut sad: Sad =
        serde_json::from_str(r#"{"d":"","n":{"z":[{"q":1,"c":null}],"a":true},"f":-1.5}"#).unwrap();
    let (said, json) = saidify(
        &mut sad,
        HashFunctionCode::Blake3_256,
        SerializationFormats::JSON,
        &["d"],
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(json).unwrap(),
        format!(r#"{{"d":"{said}","n":{{"z":[{{"q":1,"c":null}}],"a":true}},"f":-1.5}}"#)
    );
    assert_eq!(sad["d"], said.to_string());
}
