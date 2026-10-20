//! Native CESR V2 bodies, field maps and lists, enclosed non-native bodies.

use std::str::FromStr;

use cesrox::{
    parse,
    payload::Payload,
    primitives::{codes::TagCode, Primitive},
    universal_codes::{UniversalCode, UniversalGroupCode},
    Value,
};

fn tag(text: &str) -> Value {
    Value::Tag(TagCode::new(text).unwrap())
}

fn number(n: u128) -> Value {
    let text = cesrox::primitives::codes::number::pack_number(n);
    parse(text.as_bytes()).unwrap().remove(0)
}

#[test]
fn field_map_round_trips() {
    let map = Value::universal_group(
        UniversalCode::GenericMap,
        vec![tag("a"), number(1), tag("list"), {
            Value::universal_group(UniversalCode::GenericList, vec![number(2), number(3)]).unwrap()
        }],
    )
    .unwrap();
    let text = map.to_cesr();
    assert!(text.starts_with(b"-I"));

    let parsed = parse(&text).unwrap();
    assert_eq!(parsed, vec![map.clone()]);
    let entries = parsed[0].map_entries().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].0, &tag("a"));
    assert!(
        matches!(entries[1].1, Value::UniversalGroup(UniversalGroupCode::Group { code: UniversalCode::GenericList, .. }, v) if v.len() == 2)
    );
}

#[test]
fn group_content_must_fill_quadlets() {
    let json = Value::Payload(Payload::JSON(br#"{"a":1}"#.to_vec()));
    assert!(Value::universal_group(UniversalCode::GenericGroup, vec![json]).is_err());
}

#[test]
fn non_native_bodies_are_enclosed_and_recovered() {
    for payload in [
        Payload::JSON(br#"{"v":"KERICAACAAJSONAAAA.","t":"icp","k":["a","b"]}"#.to_vec()),
        Payload::MGPK(
            rmp_serde::to_vec_named(&serde_json::json!({"t": "icp", "k": ["a", "b"], "s": 1}))
                .unwrap(),
        ),
    ] {
        let enclosed = Value::non_native_body(&payload).unwrap();
        let text = enclosed.to_cesr();
        assert!(text.starts_with(b"-H"));
        let parsed = parse(&text).unwrap();
        assert_eq!(parsed[0].enclosed_payload().unwrap(), payload);
    }
    assert!(tag("a").enclosed_payload().is_err());
}

#[test]
fn messagepack_bodies_with_nested_values_are_recognised() {
    // a KERI-like message: arrays and numbers, not only strings
    let body = rmp_serde::to_vec_named(&serde_json::json!({
        "v": "KERICAACAAMGPKAAAA.", "t": "icp", "s": 0, "k": ["DA", "DB"], "a": []
    }))
    .unwrap();
    let stream = [body.clone(), b"-KAW".to_vec()].concat();
    let mut values = cesrox::values(&stream);
    assert_eq!(
        values.next().unwrap().unwrap(),
        Value::Payload(Payload::MGPK(body))
    );
    assert_eq!(values.remaining(), b"-KAW");
}

#[test]
fn primitives_inside_lists_keep_their_type() {
    let digest = "EJrL5AHH3TW5r0JoRYAGdI6HAF3DRVBzmuFFmcLRpLPq";
    let list = format!("-JAL{digest}");
    let parsed = parse(list.as_bytes()).unwrap();
    let Value::UniversalGroup(code, values) = &parsed[0] else {
        panic!("expected a group")
    };
    assert_eq!(code, &UniversalGroupCode::from_str("JAL").unwrap());
    assert!(matches!(&values[0], Value::Primitive(Primitive { raw, .. }) if raw.len() == 32));
}
