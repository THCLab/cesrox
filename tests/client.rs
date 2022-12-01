pub mod client {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    pub struct HelloCesr {
        pub name: String,
        pub surname: String,
    }
}

pub mod test {
    use cesrox::{
        group::Group,
        payload::Payload,
        primitives::codes::{basic::Basic, self_signing::SelfSigning},
    };
    use cesrox::{parse, ParsedData};

    #[test]
    pub fn test_hello_cesr() {
        use crate::client::HelloCesr;

        let cesr_stream = br#"{"name":"John","surname":"Doe"}-CABBPKahcQ56qkcaTNiGjNYUCQyfM3u-NEymzPv6tKFYthx0BC9uKulSSZ6Ta30reEA4kImQBu-wZ4hISXoSSOGKB0lBIpkLaBMjVS16A_KMsxBtE6VbL1Ry9FHJAg7ygdZbqkK"#;
        let (_rest, parsed_data) = parse::<HelloCesr>(cesr_stream).unwrap();
        match parsed_data.payload {
            Payload::JSON(json) => assert_eq!(json, br#"{"name":"John","surname":"Doe"}"#),
            Payload::CBOR(_) | Payload::MGPK(_) => unreachable!(),
        };

        let attachments = parsed_data.attachments;

        assert_eq!(attachments.len(), 1);

        let Group::NontransReceiptCouples(couples) = attachments[0].clone() else {unreachable!()};
        let ((key_code, pub_key), (sig_code, signature)) = couples[0].clone();

        assert_eq!(key_code, Basic::Ed25519Nontrans);
        assert_eq!(
            base64::encode(pub_key),
            "8pqFxDnqqRxpM2IaM1hQJDJ8ze740TKbM+/q0oVi2HE="
        );

        assert_eq!(sig_code, SelfSigning::Ed25519Sha512);
        assert_eq!(base64::encode(signature), "vbirpUkmek2t9K3hAOJCJkAbvsGeISEl6EkjhigdJQSKZC2gTI1UtegPyjLMQbROlWy9UcvRRyQIO8oHWW6pCg==");
    }

    #[test]
    pub fn test_cesr_serialization_deserialization() -> Result<(), cesrox::error::Error> {
        use crate::client::HelloCesr;
        use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer};

        let hello = HelloCesr {
            name: "John".into(),
            surname: "Doe".into(),
        };

        let seed = base64::decode("nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=").unwrap();

        let secret_key: SecretKey = SecretKey::from_bytes(&seed).unwrap();
        let public_key: PublicKey = (&secret_key).into();

        let message = serde_json::to_vec(&hello).unwrap();
        let keypair = Keypair {
            public: public_key,
            secret: secret_key,
        };
        let ed_signature: Signature = keypair.sign(&message);

        let public_key = (Basic::Ed25519Nontrans, keypair.public.as_bytes().to_vec());
        let signature = (SelfSigning::Ed25519Sha512, ed_signature.to_bytes().to_vec());

        let attachment =
            Group::NontransReceiptCouples(vec![(public_key.clone(), signature.clone())]);
        let data = ParsedData {
            payload: Payload::JSON(message),
            attachments: vec![attachment],
        };
        let cesr_stream = data.to_cesr()?;
        assert_eq!(&cesr_stream, br#"{"name":"John","surname":"Doe"}-CABBNdamAGCsQq31Uv-08lkBzoO4XLz2qYjJa8CGmj3B1Ea0BDkGKpYn5i5fhRrE57RGGonHMlwmfZBmsIAex6rPXuZqScZY3NPdyP60fDHmGjLy7kQj04vZsFBAyid1XOJxBgG"#);

        let (_rest, parsed_data) = parse::<HelloCesr>(&cesr_stream).unwrap();
        assert_eq!(
            parsed_data.payload,
            Payload::JSON(br#"{"name":"John","surname":"Doe"}"#.to_vec())
        );
        assert_eq!(
            parsed_data.attachments,
            vec![Group::NontransReceiptCouples(vec![(public_key, signature)])]
        );
        Ok(())
    }
}
