use std::str::FromStr;

use chrono::{DateTime, FixedOffset};
use nom::error::make_error;
use nom::{bytes::complete::take, error::ErrorKind, sequence::tuple};

use crate::derivation_code::DerivationCode;
use crate::error::Error;

use crate::conversion::from_text_to_bytes;
use crate::primitives::{AnchoringEventSeal, Identifier, IdentifierCode};

use super::codes::basic::Basic;
use super::codes::rand_128::Rand128Code;
use super::codes::self_addressing::SelfAddressing;
use super::codes::timestamp::TimestampCode;

pub fn parse_primitive<C: DerivationCode + FromStr<Err = Error>>(
    stream: &str,
) -> nom::IResult<&str, (C, Vec<u8>)> {
    let Ok(code) = C::from_str(stream) else {
        return Err(nom::Err::Error(make_error(stream, ErrorKind::IsNot)));
    };
    let (rest, _parsed_code) = take(code.code_size())(stream)?;
    let (rest, data) = take(code.value_size())(rest)?;
    let Ok(decoded) = from_text_to_bytes(data) else {
        return Err(nom::Err::Error(make_error(rest, ErrorKind::IsNot)));
    };
    let decoded = decoded[code.code_size() % 4..].to_vec();
    Ok((rest, (code, decoded)))
}

// Parsers for specific primitive. Meant to be used to parse group elements of
// expected type.
pub fn identifier(s: &str) -> nom::IResult<&str, Identifier> {
    let (rest, identifier) = match parse_primitive::<SelfAddressing>(s) {
        Ok(sap) => Ok((sap.0, (IdentifierCode::SelfAddressing(sap.1 .0), sap.1 .1))),
        Err(_) => match parse_primitive::<Basic>(s) {
            Ok(bp) => Ok((bp.0, (IdentifierCode::Basic(bp.1 .0), bp.1 .1))),
            Err(e) => Err(e),
        },
    }?;
    Ok((rest, identifier))
}

pub fn serial_number_parser(s: &str) -> nom::IResult<&str, u64> {
    let (rest, (_code, value)) = parse_primitive::<Rand128Code>(s)?;

    let sn = {
        let mut sn_array: [u8; 8] = [0; 8];
        sn_array.copy_from_slice(&value[8..]);
        u64::from_be_bytes(sn_array)
    };

    Ok((rest, sn))
}

pub fn timestamp_parser(s: &str) -> nom::IResult<&str, DateTime<FixedOffset>> {
    let (more, type_c) = take(4u8)(s)?;
    let Ok(code) = TimestampCode::from_str(type_c) else {
        return Err(nom::Err::Error(make_error(s, ErrorKind::IsNot)));
    };

    let (rest, parsed_timestamp) = take(code.value_size())(more)?;

    let timestamp = {
        let dt_str = parsed_timestamp
            .replace('c', ":")
            .replace('d', ".")
            .replace('p', "+");
        let Ok(dt_str) = dt_str.parse::<DateTime<FixedOffset>>() else {
            return Err(nom::Err::Error(make_error(rest, ErrorKind::IsNot)));
        };
        dt_str
    };

    Ok((rest, timestamp))
}

pub fn anchoring_event_seal(s: &str) -> nom::IResult<&str, AnchoringEventSeal> {
    let (rest, (identifier, serial_number, digest)) = tuple((
        identifier,
        serial_number_parser,
        parse_primitive::<SelfAddressing>,
    ))(s)?;

    Ok((rest, (identifier, serial_number, digest)))
}
#[cfg(test)]
pub mod tests {

    #[cfg(feature = "cesr-proof")]
    use crate::cesr_proof::{parsers::material_path, MaterialPath};
    use crate::{
        parse_one,
        primitives::{
            codes::{
                attached_signature_code::{AttachedSignatureCode, Index},
                basic::Basic,
                rand_128::Rand128Code,
                self_addressing::SelfAddressing,
                self_signing::SelfSigning,
                PrimitiveCode,
            },
            parsers::{parse_primitive, serial_number_parser, timestamp_parser},
        },
    };

    #[test]
    fn test_indexed_signature() {
        assert_eq!(
        parse_primitive::<AttachedSignatureCode>("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        Ok(("", (AttachedSignatureCode::new_from_ints(SelfSigning::Ed25519Sha512,0,Some(0)), vec![0u8; 64])))
    );

        assert_eq!(
        parse_primitive::<AttachedSignatureCode>("BCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        Ok(("AA", (AttachedSignatureCode::new_from_ints(SelfSigning::Ed25519Sha512, 2, None), vec![0u8; 64])))
    );

        let expected_sig = base64::decode_config("mdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ==", base64::URL_SAFE).unwrap();
        assert_eq!(
        parse_primitive::<AttachedSignatureCode>("AACZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ"),
        Ok(("", (AttachedSignatureCode::new_from_ints(SelfSigning::Ed25519Sha512, 0, Some(0)), expected_sig)))

    );

        let st = r#"ADCUl2Vfq-Px20g--Pl5hBXgj9rPNDqNgFhxiHibL229SQKgKrvO3rDfCeF-tWdWUhDr6mKHJPvBmLo-LitPZ4wI"#;
        assert!(matches!(
            parse_primitive::<AttachedSignatureCode>(st),
            Ok((
                _,
                (
                    AttachedSignatureCode {
                        code: SelfSigning::Ed25519Sha512,
                        index: Index::BothSame(3)
                    },
                    _
                )
            ))
        ));

        let st = r#"2AADACCUl2Vfq-Px20g--Pl5hBXgj9rPNDqNgFhxiHibL229SQKgKrvO3rDfCeF-tWdWUhDr6mKHJPvBmLo-LitPZ4wI"#;
        assert!(matches!(
            parse_primitive::<AttachedSignatureCode>(st),
            Ok((
                _,
                (
                    AttachedSignatureCode {
                        code: SelfSigning::Ed25519Sha512,
                        index: Index::BigDual(3, 2)
                    },
                    _
                )
            ))
        ));

        let st = r#"2ABaBBCZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ"#;
        assert!(matches!(
            parse_primitive::<AttachedSignatureCode>(st),
            Ok((
                _,
                (
                    AttachedSignatureCode {
                        code: SelfSigning::Ed25519Sha512,
                        index: Index::BigDual(90, 65)
                    },
                    _
                )
            ))
        ));

        let st = r#"2BBEAACZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ"#;
        assert!(matches!(
            parse_primitive::<AttachedSignatureCode>(st),
            Ok((
                _,
                (
                    AttachedSignatureCode {
                        code: SelfSigning::Ed25519Sha512,
                        index: Index::BigCurrentOnly(68)
                    },
                    _
                )
            ))
        ));
    }

    #[test]
    fn test_basic_identifier() {
        let pk_raw = vec![
            249, 247, 209, 34, 220, 90, 114, 42, 247, 149, 69, 221, 219, 244, 123, 60, 41, 37, 217,
            217, 199, 132, 199, 134, 143, 65, 11, 79, 135, 11, 85, 16,
        ];
        let str_to_parse = "DPn30SLcWnIq95VF3dv0ezwpJdnZx4THho9BC0-HC1UQmore";

        let parsed = parse_primitive::<Basic>(str_to_parse).unwrap();
        assert_eq!(parsed, ("more", (Basic::Ed25519, pk_raw)))
    }

    #[test]
    fn test_digest() {
        let digest_raw = vec![
            176, 185, 47, 120, 129, 84, 62, 251, 119, 243, 24, 109, 129, 134, 9, 68, 32, 169, 0,
            99, 187, 90, 56, 199, 85, 29, 251, 61, 172, 47, 235, 177,
        ];
        let sai_str = "ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux";
        let str_to_parse = [&sai_str, "more"].join("");
        assert_eq!(
            parse_primitive::<SelfAddressing>(&str_to_parse),
            Ok(("more", (SelfAddressing::Blake3_256, digest_raw)))
        );
    }

    #[test]
    fn test_signature() {
        let signature_string =
        "0Bq1UBr1QD5TokdcnO_FmnoYsd8rB4_-oaQtk0dfFSSXPcxAu7pSaQIVfkhzckCVmTIgrdxyXS21uZgs7NxoyZAQ";
        let string_to_parse = [&signature_string, "more"].join("");

        let signature_raw = vec![
            181, 80, 26, 245, 64, 62, 83, 162, 71, 92, 156, 239, 197, 154, 122, 24, 177, 223, 43,
            7, 143, 254, 161, 164, 45, 147, 71, 95, 21, 36, 151, 61, 204, 64, 187, 186, 82, 105, 2,
            21, 126, 72, 115, 114, 64, 149, 153, 50, 32, 173, 220, 114, 93, 45, 181, 185, 152, 44,
            236, 220, 104, 201, 144, 16,
        ];

        assert_eq!(
            parse_primitive::<SelfSigning>(&string_to_parse),
            Ok(("more", (SelfSigning::Ed25519Sha512, signature_raw)))
        );
    }

    #[test]
    fn test_sn_parse() {
        let sn = serial_number_parser("0AAAAAAAAAAAAAAAAAAAAAAD").unwrap();
        assert_eq!(sn, ("", 3));
    }

    #[test]
    pub fn test_timestamp_parse() {
        let timestamp_str = "1AAG2020-08-22T17c50c09d988921p00c00";
        let (_rest, parsed_datetime) = timestamp_parser(timestamp_str).unwrap();
        assert_eq!(
            "2020-08-22 17:50:09.988921 +00:00",
            parsed_datetime.to_string()
        );
    }

    #[cfg(feature = "cesr-proof")]
    #[test]
    fn test_path_parse() {
        let attached_str = "6AABAAA-";
        let (_rest, attached_material) = material_path(attached_str).unwrap();
        assert_eq!(attached_material, MaterialPath::to_path("-".into()));
    }

    #[test]
    fn parse_tag() {
        use crate::derivation_code::DerivationCode;
        use crate::primitives::codes::TagCode;
        let expected = "XABC";
        let (_rest, parsed_tag) = parse_primitive::<TagCode>(expected).unwrap();
        assert_eq!(&parsed_tag.0.to_str(), expected);

        let expected = "XRFI";
        let (_rest, parsed_tag) = parse_primitive::<TagCode>(expected).unwrap();
        assert_eq!(&parsed_tag.0.to_str(), expected);
    }

    #[test]
    pub fn parse_random() {
        let random = "0ACV-uxu4r8Y6ooO8Bo1DIwy";
        let (rest, parsed_random) = parse_one(random).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed_random.to_string(), random);
    }
}
