use sad_macros::SAD;
use said::sad::SAD;
use said::{derivation::HashFunctionCode, SelfAddressingIdentifier};
use serde::Serialize;
use version::serialization_info::SerializationFormats;

#[derive(SAD, Debug, Serialize)]
struct Something {
    #[said]
    i: Option<SelfAddressingIdentifier>,
    something: AdditionalThings,
    #[said]
    d: Option<SelfAddressingIdentifier>,
}
impl Something {
    pub fn new(something: AdditionalThings) -> Self {
        Self {
            something,
            i: None,
            d: None,
        }
    }
}

#[derive(Serialize, Debug, Clone)]
enum AdditionalThings {
    One,
}

#[test]
fn test_compute_digest() {
    let something = Something::new(AdditionalThings::One);
    assert!(something.d.is_none());
    assert!(something.i.is_none());

    let hash_code = HashFunctionCode::Blake3_256;
    let said_something = something.compute_digest(hash_code, SerializationFormats::JSON);

    let expected_said: SelfAddressingIdentifier = "EOnsx91HNH1JRUWYgOO-hjrWzZltTuwd8NzYkHnxmpFP"
        .parse()
        .unwrap();
    assert_eq!(said_something.d, Some(expected_said.clone()));
    assert_eq!(said_something.i, Some(expected_said.clone()));

    let something_json = serde_json::to_string(&said_something).unwrap();
    let dummy_something = format!(
        r##"{{"i":"{}","something":"One","d":"{}"}}"##,
        "#".repeat(44),
        "#".repeat(44)
    );
    assert!(expected_said.verify_binding(dummy_something.as_bytes()));
    assert_eq!(
        r#"{"i":"EOnsx91HNH1JRUWYgOO-hjrWzZltTuwd8NzYkHnxmpFP","something":"One","d":"EOnsx91HNH1JRUWYgOO-hjrWzZltTuwd8NzYkHnxmpFP"}"#,
        something_json
    );
}
