//! The binary domain (qb2): groups interleaved with text-domain groups and
//! bodies, recognised by their first bits.

use cesrox::{
    cold_start::{cold_start, ColdStart},
    conversion::qb64_to_qb2,
    group::Group,
    parse,
    payload::Payload,
    primitives::{
        codes::{
            attached_signature_code::{AttachedSignatureCode, Index},
            self_signing::SelfSigning,
        },
        IndexedSignature,
    },
    universal_codes::UniversalCode,
    values, Error, Value,
};

fn signatures() -> Value {
    let sigs = (0..2)
        .map(|i| {
            IndexedSignature::new(
                AttachedSignatureCode::new(SelfSigning::Ed25519Sha512, Index::BothSame(i)),
                vec![i as u8 + 1; 64],
            )
        })
        .collect();
    Value::SpecificGroup(Group::IndexedControllerSignatures(sigs))
}

#[test]
fn domains_and_bodies_interleave() {
    let body = Value::Payload(Payload::JSON(br#"{"a":1}"#.to_vec()));
    let attachments =
        Value::universal_group(UniversalCode::Attachments, vec![signatures()]).unwrap();

    // body, attachments in binary, attachments in text, attachments in binary
    let stream = [
        body.to_cesr(),
        attachments.to_qb2().unwrap(),
        attachments.to_cesr(),
        attachments.to_qb2().unwrap(),
    ]
    .concat();
    assert_eq!(
        cold_start(&stream[7..]),
        Some(ColdStart::BinaryCountOrOpCode)
    );

    let parsed = parse(&stream).unwrap();
    assert_eq!(
        parsed,
        vec![body, attachments.clone(), attachments.clone(), attachments]
    );
}

#[test]
fn binary_group_arriving_in_pieces() {
    let group = signatures().to_qb2().unwrap();
    let mut reader = values(&group[..group.len() - 10]);
    assert!(matches!(reader.next(), Some(Err(Error::Incomplete { .. }))));
    assert_eq!(reader.remaining().len(), group.len() - 10);
    assert_eq!(parse(&group).unwrap(), vec![signatures()]);
}

#[test]
fn bodies_inside_groups_have_no_binary_form() {
    let body = Value::Payload(Payload::JSON(br#"{"abcdef":1}"#.to_vec()));
    let group = Value::universal_group(UniversalCode::BodyWithAttachments, vec![body]).unwrap();
    assert!(group.to_qb2().is_err());
    assert!(qb64_to_qb2(b"-KA").is_err());
}

#[test]
fn annotated_example_from_the_spec() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test-vectors/v2/spec/streams/messages.json"
    );
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let file: serde_json::Value = serde_json::from_str(&text).unwrap();
    let vector = &file["vectors"][0];
    let annotated = vector["annotated"].as_str().unwrap().as_bytes();
    assert_eq!(cold_start(annotated), Some(ColdStart::TextCountCode));

    let plain = cesrox::cold_start::deannotate(annotated);
    assert_eq!(plain, vector["stream"].as_str().unwrap().as_bytes());
    let parsed = parse(&plain).unwrap();
    let [Value::SpecificGroup(Group::TransIdxSigGroups(groups))] = parsed.as_slice() else {
        panic!("expected one -X group, got {parsed:?}")
    };
    assert_eq!(groups[0].signatures.len(), 3);
    assert_eq!(groups[0].sn, 0);
}
