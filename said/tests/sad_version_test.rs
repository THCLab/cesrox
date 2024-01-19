#[cfg(feature = "macros")]
mod tests {
    use std::str::FromStr;

    use said::derivation::HashFunctionCode;
    use said::version::SerializationInfo;
    use said::{
        sad::{SerializationFormats, SAD},
        SelfAddressingIdentifier,
    };
    use serde::Serialize;

    #[test]
    pub fn test_version() {
        #[derive(SAD, Serialize)]
        #[version(protocol = "KERI", major = 1, minor = 0)]
        struct VersionSomething {
            pub text: String,
        }

        let something = VersionSomething {
            text: "Hello world".to_string(),
        };

        let code = HashFunctionCode::Blake3_256;
        let format = SerializationFormats::JSON;
        let derivation_data = something.derivation_data(&code, &format);

        assert_eq!(
            format!(r#"{{"v":"KERI10JSON00002e_","text":"Hello world"}}"#,),
            String::from_utf8(derivation_data.clone()).unwrap()
        );
        let version = SerializationInfo::from_str("KERI10JSON00002e_").unwrap();
        assert_eq!(version.size, derivation_data.len())
    }

    #[test]
    pub fn test_said_version() {
        #[derive(SAD, Serialize)]
        #[version(protocol = "KERI", major = 1, minor = 0)]
        struct VersionSomething {
            pub text: String,
            #[said]
            pub d: Option<SelfAddressingIdentifier>,
        }

        let mut something = VersionSomething {
            text: "Hello world".to_string(),
            d: None,
        };

        let code = HashFunctionCode::SHA3_256;
        let format = SerializationFormats::JSON;
        something.compute_digest(&code, &format);
        let computed_digest = something.d.as_ref();
        let derivation_data = something.derivation_data(&code, &format);

        assert_eq!(
            format!(
                r#"{{"v":"KERI10JSON000061_","text":"Hello world","d":"{}"}}"#,
                "############################################"
            ),
            String::from_utf8(derivation_data.clone()).unwrap()
        );

        assert_eq!(
            computed_digest,
            Some(
                &"HOVTCXQaBl9zewC1YXev3lkPbbW1Mjtwp-nmnLcuUSOJ"
                    .parse()
                    .unwrap()
            )
        );
        assert!(something
            .d
            .as_ref()
            .unwrap()
            .verify_binding(&something.derivation_data(&code, &format)));
    }

    #[derive(Debug, Clone, Serialize)]
    struct AdditionalThings {
        number: u16,
        text: String,
    }

    #[test]
    fn test_nested_said_version() {
        #[derive(SAD, Debug, Serialize, Clone)]
        #[version(protocol = "KERI", major = 1, minor = 0)]
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

        let code = HashFunctionCode::Blake3_256;
        let format = SerializationFormats::JSON;
        let mut something = GenericSomething::new(AdditionalThings {
            number: 1,
            text: "Hello".to_string(),
        });
        assert!(something.clone().digest.is_none());
        assert!(something.clone().i.is_none());

        something.compute_digest(&code, &format);

        let something_json = serde_json::to_string(&something).unwrap();
        let expected_derivation_data = format!(
            r##"{{"v":"KERI10JSON000099_","i":"{}","number":1,"text":"Hello","d":"{}"}}"##,
            "#".repeat(44),
            "#".repeat(44),
        );

        assert_eq!(
            expected_derivation_data,
            String::from_utf8(something.derivation_data(&code, &format)).unwrap()
        );

        assert!(something
            .digest
            .as_ref()
            .unwrap()
            .verify_binding(&something.derivation_data(&code, &format)));
        assert_eq!(
            r#"{"i":"EBtZDCPH4D1ko0Ac8xFe21Av-awNriwONHia3C9ZKZ6y","number":1,"text":"Hello","d":"EBtZDCPH4D1ko0Ac8xFe21Av-awNriwONHia3C9ZKZ6y"}"#,
            something_json
        );
    }
}
