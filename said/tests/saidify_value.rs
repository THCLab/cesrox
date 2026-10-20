//! SAIDs of serde types and verification of received messages. The SAIDs
//! are the ones the earlier `SAD` derive computed for the same data, so
//! data saidified with it still verifies.

use said::{
    derivation::HashFunctionCode,
    sad::SerializationFormats,
    saidify, saidify_value, verify,
    version::{error::Error, SerializationInfo},
    Sad, SelfAddressingIdentifier,
};
use serde::{Deserialize, Serialize};

const FORMATS: [SerializationFormats; 3] = [
    SerializationFormats::JSON,
    SerializationFormats::CBOR,
    SerializationFormats::MGPK,
];

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct Something {
    text: String,
    d: Option<SelfAddressingIdentifier>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct AdditionalThings {
    number: u16,
    text: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct Inception<D> {
    #[serde(skip_serializing_if = "Option::is_none")]
    v: Option<SerializationInfo>,
    i: Option<SelfAddressingIdentifier>,
    #[serde(flatten)]
    something: D,
    #[serde(rename = "d")]
    digest: Option<SelfAddressingIdentifier>,
}

impl<D> Inception<D> {
    fn new(version: Option<SerializationInfo>, something: D) -> Self {
        Self {
            v: version,
            i: None,
            something,
            digest: None,
        }
    }
}

fn additional() -> AdditionalThings {
    AdditionalThings {
        number: 1,
        text: "Hello".into(),
    }
}

fn keri_1(format: SerializationFormats) -> Option<SerializationInfo> {
    Some(SerializationInfo::new_empty("KERI".into(), 1, 0, format))
}

#[test]
fn saidifies_a_struct() {
    let mut something = Something {
        text: "Hello world".into(),
        d: None,
    };
    let (said, message) = saidify_value(
        &mut something,
        HashFunctionCode::Blake3_256,
        SerializationFormats::JSON,
        &["d"],
    )
    .unwrap();

    let expected: SelfAddressingIdentifier = "EF-7wdNGXqgO4aoVxRpdWELCx_MkMMjx7aKg9sqzjKwI"
        .parse()
        .unwrap();
    assert_eq!(said, expected);
    assert_eq!(something.d, Some(expected));
    assert_eq!(message, serde_json::to_vec(&something).unwrap());
}

#[test]
fn fills_several_fields_through_flatten_and_renames() {
    let mut inception = Inception::new(None, additional());
    let (said, message) = saidify_value(
        &mut inception,
        HashFunctionCode::Blake3_256,
        SerializationFormats::JSON,
        &["i", "d"],
    )
    .unwrap();

    assert_eq!(
        String::from_utf8(message).unwrap(),
        r#"{"i":"EK8SVw6LHLtOFPOu9szLFV8Ji-yEnAkhjAAmQ4HtPWdM","number":1,"text":"Hello","d":"EK8SVw6LHLtOFPOu9szLFV8Ji-yEnAkhjAAmQ4HtPWdM"}"#
    );
    assert_eq!(inception.i, Some(said.clone()));
    assert_eq!(inception.digest, Some(said));
    assert_eq!(inception.something, additional());
}

#[test]
fn fills_in_the_version_string() {
    let format = SerializationFormats::JSON;
    let mut something = Inception {
        v: keri_1(format),
        i: None,
        something: additional(),
        digest: None,
    };
    let (said, message) = saidify_value(
        &mut something,
        HashFunctionCode::Blake3_256,
        format,
        &["i", "d"],
    )
    .unwrap();

    assert_eq!(
        said,
        "EBtZDCPH4D1ko0Ac8xFe21Av-awNriwONHia3C9ZKZ6y"
            .parse()
            .unwrap()
    );
    let version = something.v.unwrap();
    assert_eq!(version.to_str(), "KERI10JSON000099_");
    assert_eq!(version.size, message.len());
}

#[test]
fn any_digest_code() {
    #[derive(Serialize, Deserialize)]
    struct Versioned {
        v: SerializationInfo,
        text: String,
        d: Option<SelfAddressingIdentifier>,
    }
    let format = SerializationFormats::JSON;
    let mut versioned = Versioned {
        v: keri_1(format).unwrap(),
        text: "Hello world".into(),
        d: None,
    };
    let (said, message) =
        saidify_value(&mut versioned, HashFunctionCode::SHA3_256, format, &["d"]).unwrap();
    assert_eq!(
        said,
        "HOVTCXQaBl9zewC1YXev3lkPbbW1Mjtwp-nmnLcuUSOJ"
            .parse()
            .unwrap()
    );
    assert!(String::from_utf8(message)
        .unwrap()
        .starts_with(r#"{"v":"KERI10JSON000061_""#));
}

#[test]
fn matches_saidify_in_every_format() {
    let code = HashFunctionCode::Blake3_256;
    for format in FORMATS {
        let mut inception = Inception::new(
            Some(SerializationInfo::new_empty("KERI".into(), 2, 0, format)),
            additional(),
        );
        let (said, message) = saidify_value(&mut inception, code.clone(), format, &["d"]).unwrap();

        let mut sad: Sad = serde_json::from_str(
            r#"{"v":"KERICAACAAJSONAAAA.","i":null,"number":1,"text":"Hello","d":""}"#,
        )
        .unwrap();
        let (expected, expected_message) = saidify(&mut sad, code.clone(), format, &["d"]).unwrap();
        assert_eq!(said, expected, "{format:?}");
        assert_eq!(message, expected_message, "{format:?}");
    }
}

#[test]
fn cbor_maps_have_a_definite_length() {
    let mut something = Something {
        text: "Hello world".into(),
        d: None,
    };
    let (_, message) = saidify_value(
        &mut something,
        HashFunctionCode::Blake3_256,
        SerializationFormats::CBOR,
        &["d"],
    )
    .unwrap();
    // 0xa2: a map of two entries, not 0xbf (indefinite length)
    assert_eq!(message[0], 0xa2);
}

#[test]
fn a_said_field_must_be_serialized() {
    #[derive(Serialize, Deserialize)]
    struct Skipping {
        #[serde(skip_serializing_if = "Option::is_none")]
        d: Option<SelfAddressingIdentifier>,
    }
    let result = saidify_value(
        &mut Skipping { d: None },
        HashFunctionCode::Blake3_256,
        SerializationFormats::JSON,
        &["d"],
    );
    assert!(matches!(result, Err(Error::MissingField(_))));
}

#[test]
fn only_maps_and_serializable_formats() {
    let code = HashFunctionCode::Blake3_256;
    let result = saidify_value(
        &mut vec![1, 2],
        code.clone(),
        SerializationFormats::JSON,
        &["d"],
    );
    assert!(matches!(result, Err(Error::SerializationError(_))));

    let mut something = Something {
        text: "Hello".into(),
        d: None,
    };
    assert!(saidify_value(&mut something, code, SerializationFormats::CESR, &["d"]).is_err());
}

#[test]
fn verifies_messages_in_every_format() {
    for format in FORMATS {
        let mut inception = Inception::new(
            Some(SerializationInfo::new_empty("KERI".into(), 2, 0, format)),
            additional(),
        );
        let (said, message) = saidify_value(
            &mut inception,
            HashFunctionCode::Blake3_256,
            format,
            &["i", "d"],
        )
        .unwrap();
        assert_eq!(
            verify(&message, format, &["i", "d"]).unwrap(),
            said,
            "{format:?}"
        );
        // every field that held a placeholder must be named
        assert!(verify(&message, format, &["d"]).is_err(), "{format:?}");
    }
}

fn signed_message() -> String {
    let mut inception = Inception::new(keri_1(SerializationFormats::JSON), additional());
    let (_, message) = saidify_value(
        &mut inception,
        HashFunctionCode::Blake3_256,
        SerializationFormats::JSON,
        &["i", "d"],
    )
    .unwrap();
    String::from_utf8(message).unwrap()
}

#[test]
fn rejects_changed_data() {
    let forged = signed_message().replace("Hello", "Hallo");
    assert!(matches!(
        verify(forged.as_bytes(), SerializationFormats::JSON, &["d"]),
        Err(Error::InvalidSaid(_))
    ));
}

#[test]
fn rejects_another_encoding_of_the_same_map() {
    let spaced = signed_message().replace(r#","number""#, r#", "number""#);
    assert!(matches!(
        verify(spaced.as_bytes(), SerializationFormats::JSON, &["d"]),
        Err(Error::InvalidSaid(_))
    ));
}

#[test]
fn rejects_a_wrong_version_string() {
    let message = signed_message();
    // the size is right for JSON, but the message is read as another kind
    let as_cbor = message.replace("JSON", "CBOR");
    assert!(matches!(
        verify(as_cbor.as_bytes(), SerializationFormats::JSON, &["d"]),
        Err(Error::InvalidSaid(_))
    ));
}

#[test]
fn rejects_differing_said_fields() {
    let message = signed_message();
    let other = "EF-7wdNGXqgO4aoVxRpdWELCx_MkMMjx7aKg9sqzjKwI";
    let i = message.find(r#""i":""#).unwrap() + 5;
    let message = format!("{}{other}{}", &message[..i], &message[i + other.len()..]);
    assert!(matches!(
        verify(message.as_bytes(), SerializationFormats::JSON, &["i", "d"]),
        Err(Error::InvalidSaid(_))
    ));
    // `i` is part of what `d` is the SAID of
    assert!(verify(message.as_bytes(), SerializationFormats::JSON, &["d"]).is_err());
}

#[test]
fn reports_missing_and_malformed_fields() {
    let message = signed_message();
    let json = SerializationFormats::JSON;
    assert!(matches!(
        verify(message.as_bytes(), json, &["x"]),
        Err(Error::MissingField(_))
    ));
    assert!(matches!(
        verify(message.as_bytes(), json, &["text"]),
        Err(Error::InvalidSaid(_))
    ));
    assert!(matches!(
        verify(message.as_bytes(), json, &[]),
        Err(Error::MissingField(_))
    ));
    assert!(verify(b"not json", json, &["d"]).is_err());
    assert!(verify(message.as_bytes(), SerializationFormats::CESR, &["d"]).is_err());
}
