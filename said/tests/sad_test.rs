use sad_macros::SAD;
use said::sad::SAD;
use said::{derivation::HashFunctionCode, SelfAddressingIdentifier};
use serde::Serialize;
use version::serialization_info::SerializationFormats;

#[derive(SAD, Debug, Serialize, Clone)]
struct Something<D>
where
    D: Serialize + Clone,
{
    #[said]
    i: Option<SelfAddressingIdentifier>,
    #[serde(flatten)]
    something: D,
    #[said]
    #[serde(rename = "d")]
    digest: Option<SelfAddressingIdentifier>,
}
impl<D> Something<D>
where
    D: Serialize + Clone,
{
    pub fn new(something: D) -> Self {
        Self {
            something,
            i: None,
            digest: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct AdditionalThings {
    number: u16,
    text: String,
}

#[test]
fn test_compute_digest() {
    let something = Something::new(AdditionalThings {
        number: 1,
        text: "Hello".to_string(),
    });
    assert!(something.clone().digest.is_none());
    assert!(something.clone().i.is_none());

    let hash_code = HashFunctionCode::Blake3_256;
    let said_something = something.compute_digest(hash_code.clone(), SerializationFormats::JSON);

    println!("{}", said_something.derivative(&hash_code, &SerializationFormats::JSON));

    let expected_said: SelfAddressingIdentifier = "EK8SVw6LHLtOFPOu9szLFV8Ji-yEnAkhjAAmQ4HtPWdM"
        .parse()
        .unwrap();
    assert_eq!(said_something.clone().digest, Some(expected_said.clone()));
    assert_eq!(said_something.clone().i, Some(expected_said.clone()));

    let something_json = serde_json::to_string(&said_something).unwrap();
    let dummy_something = format!(
        r##"{{"i":"{}","number":1,"text":"Hello","d":"{}"}}"##,
        "#".repeat(44),
        "#".repeat(44)
    );
    assert!(expected_said.verify_binding(dummy_something.as_bytes()));
    assert_eq!(
        r#"{"i":"EK8SVw6LHLtOFPOu9szLFV8Ji-yEnAkhjAAmQ4HtPWdM","number":1,"text":"Hello","d":"EK8SVw6LHLtOFPOu9szLFV8Ji-yEnAkhjAAmQ4HtPWdM"}"#,
        something_json
    );
}
