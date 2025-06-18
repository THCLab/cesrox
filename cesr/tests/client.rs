pub mod test {
    use cesrox::{
        group::Group,
        parse_all,
        payload::Payload,
        primitives::codes::{basic::Basic, self_signing::SelfSigning},
        value::Value,
    };

    #[test]
    pub fn test_hello_cesr() {
        let cesr_stream = r#"{"name":"John","surname":"Doe"}-MABBPKahcQ56qkcaTNiGjNYUCQyfM3u-NEymzPv6tKFYthx0BC9uKulSSZ6Ta30reEA4kImQBu-wZ4hISXoSSOGKB0lBIpkLaBMjVS16A_KMsxBtE6VbL1Ry9FHJAg7ygdZbqkK"#;

        let (_rest, values) = parse_all(cesr_stream).unwrap();
        assert_eq!(values.len(), 2);

        match &values[0] {
            Value::Payload(Payload::JSON(json)) => {
                assert_eq!(json, br#"{"name":"John","surname":"Doe"}"#)
            }
            _ => unreachable!(),
        };

        let Value::SpecificGroup(Group::NontransReceiptCouples(couples)) = &values[1] else {
            unreachable!()
        };
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
        use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer};

        let seed = base64::decode("nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=").unwrap();

        let secret_key: SecretKey = SecretKey::from_bytes(&seed).unwrap();
        let public_key: PublicKey = (&secret_key).into();

        let message = br#"{"name":"John","surname":"Doe"}"#;
        let keypair = Keypair {
            public: public_key,
            secret: secret_key,
        };
        let ed_signature: Signature = keypair.sign(message);

        let public_key = (Basic::Ed25519Nontrans, keypair.public.as_bytes().to_vec());
        let signature = (SelfSigning::Ed25519Sha512, ed_signature.to_bytes().to_vec());

        let attachment =
            Group::NontransReceiptCouples(vec![(public_key.clone(), signature.clone())]);

        let payload = Payload::JSON(message.to_vec());

        let values = vec![Value::Payload(payload), Value::SpecificGroup(attachment)];
        let cesr_stream = values
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("");

        assert_eq!(
            &cesr_stream,
            r#"{"name":"John","surname":"Doe"}-MABBNdamAGCsQq31Uv-08lkBzoO4XLz2qYjJa8CGmj3B1Ea0BDkGKpYn5i5fhRrE57RGGonHMlwmfZBmsIAex6rPXuZqScZY3NPdyP60fDHmGjLy7kQj04vZsFBAyid1XOJxBgG"#
        );

        let (_rest, parsed_data) = parse_all(&cesr_stream).unwrap();
        assert_eq!(parsed_data, values);

        Ok(())
    }

    #[test]
    fn test_incomplete_stream() {
        let cesr_stream = r#"{"hello":"world"}-SABEECGIp5CTCJZlZg-kap5Ma04x_tP_xWG90oKRPTW0Geq0AAAAAAAAAAAAAAAAAAAAAAAEECGIp5CTCJZlZg-kap5Ma04x_tP_xWG90oKRPTW0Geq-KABAAArmG_maHPKlUvMXkJfEysM_ej84lWdbtJXYWlrOBkhM1td1idMU0wUIBm5XkaRIw78QmFHUrYoi_kkryhJJy8J-MABBDg3H7Sr-eES0XWXiO8nvMxW6mD_1LxLeE1nuiZxhGp40BBFHf56jD6v15vWezesWY-RPj2ZiXGC-"#;

        let (rest, values) = parse_all(cesr_stream).expect("Invalid CESR stream");
        assert_eq!(values.len(), 3);
        assert_eq!(
            rest,
            "-CABBDg3H7Sr-eES0XWXiO8nvMxW6mD_1LxLeE1nuiZxhGp40BBFHf56jD6v15vWezesWY-RPj2ZiXGC-"
        );
    }

    // #[test]
    // fn test_parse_and_send() {
    //     let input = r#"{"v":"KERI10JSON000188_","t":"icp","d":"EJ11vJy_lLwv-lWGZnjhuWUh4EjMQyyMHRH1-uDAxiLg","i":"EJ11vJy_lLwv-lWGZnjhuWUh4EjMQyyMHRH1-uDAxiLg","s":"0","kt":"1","k":["DA4cgeFcpglZf6fQ7u1j8fMs7GbkOQBzVHhBJlaHQLC9"],"nt":"1","n":["EJMujtnS0x3RGp_kHC2bh3p6cAz_4nKp6E3Yrj2u-Lsh"],"bt":"2","b":["BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","BDg1zxxf8u4Hx5IPraZzmStfSCZFZbDzMHjqVcFW5OfP"],"c":[],"a":[]}-AABAADZCv1YufmwIvFbzC9jNoVZx2ZgOF8hzrxcuP9vlhJ0tNAYIvNEh0yKIGtkk1bIhrLIAEScbBmxxPosX-rGSAsD-CABBDg1zxxf8u4Hx5IPraZzmStfSCZFZbDzMHjqVcFW5OfP0BCQwOrc3LZqdYs8OEKhQlP4LpB9AqCVpwyGHCB1nfjrBjSYiWtlcvSYI5Vugh3H3rh0gfDqGHUfRKEQrIXKTWAC-CABBJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC0BCO8ycCB9reZHhv7wT4yEAy-q_IFbCA29ttaU3IcQ1tZAIGNKYNkZMY9EjGfRsq8shizeURuoxdYoRXGscQFVQM{"v":"KERI10JSON000160_","t":"rot","d":"EO3KriXb_p3p4dWuG87UIILNR5CsqNClvuc08oRWaAl5","i":"EJ11vJy_lLwv-lWGZnjhuWUh4EjMQyyMHRH1-uDAxiLg","s":"1","p":"EJ11vJy_lLwv-lWGZnjhuWUh4EjMQyyMHRH1-uDAxiLg","kt":"1","k":["BMUt1GfFIZXF_2dI1AGBEdmHjMDsSQOGSORU3igbzSvD"],"nt":"1","n":["ELSdoQmwS1FA2p0d1rlabH8nogFS_-ehA1D45kAmYkkJ"],"bt":"1","br":[],"ba":[],"a":[]}-AABAABXD4O4zkPCDSSTUPCVfFy3fFN4ycOKfUoGd-WOXHflJIGaU137PE6ututuwU8xClsES5ByLw8ytvZw4I1mXRgL-CABBDg1zxxf8u4Hx5IPraZzmStfSCZFZbDzMHjqVcFW5OfP0BCVRmDSy-EvjDxhQXJuUgWw_XhKZ2hxQxsDMxcz9K67Lqy3g9kGevXhlP3bAbmRZ6dmWiyoA_3rYG20LJX7CA4K-CABBJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC0BDLp2_wVt_GWUNSm9BDizNWgyGCPnSXdiM5tObP3dze5ah1Me-laex_xFDozxq5beWT3XZf56pYYsdjUYv_iFsA{"v"#;

    //     let (tx, rx) = std::sync::mpsc::channel();

    //     let _ = std::thread::spawn(move || {
    //         let res = parse_and_send(input.as_bytes(), &tx);
    //         assert_eq!(
    //             res.unwrap_err(),
    //             ParsingError::ParsingError(r#"{"v"#.to_string())
    //         );
    //     })
    //     .join();

    //     let received = rx.iter().collect::<Vec<_>>();
    //     assert_eq!(received.len(), 2);
    // }
}
