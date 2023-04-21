#[cfg(feature = "macros")]
mod tests {
    use said::sad::SAD;
    use said::{derivation::HashFunctionCode, SelfAddressingIdentifier};
    use serde::Serialize;
    use version::serialization_info::SerializationFormats;

    #[test]
    pub fn basic_derive_test() {
        #[derive(SAD, Serialize)]
        struct Something {
            pub text: String,
            #[said]
            pub d: Option<SelfAddressingIdentifier>,
        }

        let mut something = Something {
            text: "Hello world".to_string(),
            d: None,
        };

        something.compute_digest(HashFunctionCode::Blake3_256, SerializationFormats::JSON);
        let computed_digest = something.d.as_ref();
        let derivation_data =
            something.derivation_data(&HashFunctionCode::Blake3_256, &SerializationFormats::JSON);
        let saided = serde_json::to_string(&something).unwrap();

        assert_eq!(
            format!(
                r#"{{"text":"Hello world","d":"{}"}}"#,
                "############################################"
            )
            .as_bytes(),
            &derivation_data
        );
        assert_eq!(
            r#"{"text":"Hello world","d":"EF-7wdNGXqgO4aoVxRpdWELCx_MkMMjx7aKg9sqzjKwI"}"#,
            saided
        );

        assert_eq!(
            computed_digest,
            Some(
                &"EF-7wdNGXqgO4aoVxRpdWELCx_MkMMjx7aKg9sqzjKwI"
                    .parse()
                    .unwrap()
            )
        );
        assert!(something.d.as_ref().unwrap().verify_binding(
            &something.derivation_data(&HashFunctionCode::Blake3_256, &SerializationFormats::JSON)
        ));
    }

    #[derive(SAD, Debug, Serialize, Clone)]
    struct GenericSomething<D>
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
    impl<D> GenericSomething<D>
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
        let mut something = GenericSomething::new(AdditionalThings {
            number: 1,
            text: "Hello".to_string(),
        });
        assert!(something.clone().digest.is_none());
        assert!(something.clone().i.is_none());

        let hash_code = HashFunctionCode::Blake3_256;
        something.compute_digest(hash_code.clone(), SerializationFormats::JSON);

        let expected_said: SelfAddressingIdentifier =
            "EK8SVw6LHLtOFPOu9szLFV8Ji-yEnAkhjAAmQ4HtPWdM"
                .parse()
                .unwrap();
        assert_eq!(something.clone().digest, Some(expected_said.clone()));
        assert_eq!(something.clone().i, Some(expected_said.clone()));

        let something_json = serde_json::to_string(&something).unwrap();
        let expected_derivation_data = format!(
            r##"{{"i":"{}","number":1,"text":"Hello","d":"{}"}}"##,
            "#".repeat(44),
            "#".repeat(44)
        );

        assert_eq!(
            expected_derivation_data.as_bytes(),
            &something.derivation_data(&hash_code, &SerializationFormats::JSON)
        );

        assert!(expected_said
            .verify_binding(&something.derivation_data(&hash_code, &SerializationFormats::JSON)));
        assert_eq!(
            r#"{"i":"EK8SVw6LHLtOFPOu9szLFV8Ji-yEnAkhjAAmQ4HtPWdM","number":1,"text":"Hello","d":"EK8SVw6LHLtOFPOu9szLFV8Ji-yEnAkhjAAmQ4HtPWdM"}"#,
            something_json
        );
    }
}
