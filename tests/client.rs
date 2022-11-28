pub mod client {
    use cesrox::Payload;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    pub struct HelloCesr {
        pub name: String,
        pub surname: String,
    }
    impl HelloCesr {
        pub fn new(name: String, surname: String) -> Self {
            HelloCesr { name, surname }
        }
    }

    impl Payload for HelloCesr {
        fn to_vec(&self) -> Result<Vec<u8>, cesrox::error::Error> {
            serde_json::to_vec(self).map_err(|_e| cesrox::error::Error::PayloadSerializationError)
        }
    }
}

pub mod test {
    use cesrox::ParsedData;
    use cesrox::parsers::parse;
    use cesrox::{
        codes::{basic::Basic, self_signing::SelfSigning},
        group::Group,
    };

    #[test]
    pub fn test_hello_cesr() {
        use crate::client::HelloCesr;

        let cesr_stream = br#"{"name":"John","surname":"Doe"}-CABBPKahcQ56qkcaTNiGjNYUCQyfM3u-NEymzPv6tKFYthx0BC9uKulSSZ6Ta30reEA4kImQBu-wZ4hISXoSSOGKB0lBIpkLaBMjVS16A_KMsxBtE6VbL1Ry9FHJAg7ygdZbqkK"#;
        let (_rest, parsed_data) = parse::<HelloCesr>(cesr_stream).unwrap();
        
        let payload = parsed_data.payload;
        let attachments = parsed_data.attachments;
        assert_eq!(payload.name, "John");
        assert_eq!(payload.surname, "Doe");
        assert_eq!(attachments.len(), 1);
        let attachment = attachments[0].clone();

        let expected_public_key = (
            Basic::Ed25519NT,
            vec![
                242, 154, 133, 196, 57, 234, 169, 28, 105, 51, 98, 26, 51, 88, 80, 36, 50, 124,
                205, 238, 248, 209, 50, 155, 51, 239, 234, 210, 133, 98, 216, 113,
            ],
        );
        let expected_signature = (
            SelfSigning::Ed25519Sha512,
            vec![
                189, 184, 171, 165, 73, 38, 122, 77, 173, 244, 173, 225, 0, 226, 66, 38, 64, 27,
                190, 193, 158, 33, 33, 37, 232, 73, 35, 134, 40, 29, 37, 4, 138, 100, 45, 160, 76,
                141, 84, 181, 232, 15, 202, 50, 204, 65, 180, 78, 149, 108, 189, 81, 203, 209, 71,
                36, 8, 59, 202, 7, 89, 110, 169, 10,
            ],
        );
        assert_eq!(
            attachment,
            Group::NontransferableReceiptCouples(vec![(expected_public_key, expected_signature)])
        );
    }

    #[test]
    pub fn test_cesr_serialization_deserialization() -> Result<(), cesrox::error::Error> {
        use crate::client::HelloCesr;
        use ed25519_dalek::{Signature, Signer};
        use rand::rngs::OsRng;

        let hello = HelloCesr::new("John".into(), "Doe".into());

        let key_pair: ed25519_dalek::Keypair = ed25519_dalek::Keypair::generate(&mut OsRng {});

        let message = serde_json::to_vec(&hello).unwrap();
        let ed_signature: Signature = key_pair.sign(&message);

        let public_key = (Basic::Ed25519NT, key_pair.public.as_bytes().to_vec());
        let signature = (SelfSigning::Ed25519Sha512, ed_signature.to_bytes().to_vec());

        let attachment =
            Group::NontransferableReceiptCouples(vec![(public_key.clone(), signature.clone())]);
        let data = ParsedData {
            payload: hello,
            attachments: vec![attachment],
        };
        let cesr_stream = data.to_cesr()?;

        let (_rest, parsed_data) = parse::<HelloCesr>(&cesr_stream).unwrap();
        let payload = parsed_data.payload;
        assert_eq!(payload.name, "John");
        assert_eq!(payload.surname, "Doe");
        assert_eq!(
            parsed_data.attachments,
            vec![Group::NontransferableReceiptCouples(vec![(
                public_key, signature
            )])]
        );
        Ok(())
    }
}
