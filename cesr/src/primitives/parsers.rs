use std::str::FromStr;

use chrono::{DateTime, FixedOffset};
use nom::{bytes::complete::take, Parser};

use crate::derivation_code::DerivationCode;
use crate::error::Error;
use crate::Parsed;

use crate::conversion::from_text_to_bytes;
use crate::parsing::{ascii, code_error, error, finish, PResult};
use crate::primitives::{AnchoringEventSeal, Identifier, IdentifierCode, Primitive};

use super::codes::basic::Basic;
use super::codes::number::{number_value, NumberCode};
use super::codes::rand_128::Rand128Code;
use super::codes::self_addressing::SelfAddressing;
use super::codes::timestamp::TimestampCode;

/// Parses one primitive with a code from the table `C` at the start of
/// `input`. Returns the primitive and the rest of the input.
///
/// Use this where the context fixes the code table, e.g. indexed signatures
/// inside a signature group; [`crate::parse_value`] picks the table itself.
pub fn parse_primitive<C: DerivationCode + FromStr<Err = Error>>(
    input: &[u8],
) -> Parsed<'_, Primitive<C>> {
    finish(input, primitive::<C>(input))
}

pub(crate) fn primitive<C: DerivationCode + FromStr<Err = Error>>(
    input: &[u8],
) -> PResult<'_, Primitive<C>> {
    primitive_with(input, C::from_str)
}

/// Like [`primitive`], with the code read by `parse_code`.
pub(crate) fn primitive_with<C: DerivationCode>(
    input: &[u8],
    parse_code: impl Fn(&str) -> Result<C, Error>,
) -> PResult<'_, Primitive<C>> {
    let code = match parse_code(ascii(input)) {
        Ok(code) => code,
        Err(e) => return error(input, code_error(input, e)),
    };
    let (rest, _code) = take(code.code_size())(input)?;
    let (rest, data) = take(code.value_size())(rest)?;
    let text = ascii(data);
    if text.len() != data.len() {
        return error(input, Error::InvalidBase64);
    }
    let Ok(decoded) = from_text_to_bytes(text) else {
        return error(input, Error::InvalidBase64);
    };
    // the code takes the place of `pad` lead bytes; their bits that fall
    // into the value text must be zero, or one value has several encodings.
    // Lead bytes of the value itself must be zero as well.
    let pad = code.code_size() % 4 + code.lead_size();
    match decoded.split_at_checked(pad) {
        Some((lead, raw)) if lead.iter().all(|b| *b == 0) => {
            Ok((rest, Primitive::new(code, raw.to_vec())))
        }
        Some(_) => error(
            input,
            Error::Invalid(format!("{}: non-zero pad bits", code.to_str())),
        ),
        None => error(input, Error::IncorrectLength(code.to_str())),
    }
}

// Parsers for specific primitive. Meant to be used to parse group elements of
// expected type.
pub(crate) fn identifier(input: &[u8]) -> PResult<'_, Identifier> {
    match primitive::<SelfAddressing>(input) {
        Ok((rest, p)) => Ok((
            rest,
            Primitive::new(IdentifierCode::SelfAddressing(p.code), p.raw),
        )),
        Err(_) => primitive::<Basic>(input)
            .map(|(rest, p)| (rest, Primitive::new(IdentifierCode::Basic(p.code), p.raw))),
    }
}

/// A sequence or ordinal number: a Number primitive, or a 128-bit salt as
/// cesrox wrote it before CESR V2.
pub(crate) fn serial_number(input: &[u8]) -> PResult<'_, u128> {
    let (rest, raw) = match primitive::<NumberCode>(input) {
        Ok((rest, number)) => (rest, number.raw),
        Err(_) => primitive::<Rand128Code>(input).map(|(rest, salt)| (rest, salt.raw))?,
    };
    match number_value(&raw) {
        Ok(sn) => Ok((rest, sn)),
        Err(e) => error(input, e),
    }
}

pub(crate) fn timestamp(input: &[u8]) -> PResult<'_, DateTime<FixedOffset>> {
    let (more, code) = take(4u8)(input)?;
    if TimestampCode::from_str(ascii(code)).is_err() {
        return error(input, Error::UnknownCode);
    }
    let (rest, parsed_timestamp) = take(TimestampCode.value_size())(more)?;

    let dt_str = ascii(parsed_timestamp)
        .replace('c', ":")
        .replace('d', ".")
        .replace('p', "+");
    match dt_str.parse::<DateTime<FixedOffset>>() {
        Ok(timestamp) => Ok((rest, timestamp)),
        Err(e) => error(input, Error::Invalid(format!("timestamp: {e}"))),
    }
}

pub(crate) fn anchoring_event_seal(input: &[u8]) -> PResult<'_, AnchoringEventSeal> {
    (identifier, serial_number, primitive::<SelfAddressing>)
        .map(|(prefix, sn, digest)| AnchoringEventSeal { prefix, sn, digest })
        .parse(input)
}
#[cfg(test)]
pub mod tests {

    use base64::prelude::*;

    use std::str::FromStr;

    use chrono::{DateTime, FixedOffset};

    use crate::{
        derivation_code::DerivationCode,
        error::Error,
        parsing::on_text,
        primitives::codes::{
            attached_signature_code::{AttachedSignatureCode, Index},
            basic::Basic,
            self_addressing::SelfAddressing,
            self_signing::SelfSigning,
        },
        value::{parse_value_at, Value},
    };

    fn parse_primitive<C: DerivationCode + FromStr<Err = Error>>(
        s: &str,
    ) -> Result<(&str, (C, Vec<u8>)), Error> {
        on_text(s, super::primitive::<C>).map(|(rest, p)| (rest, (p.code, p.raw)))
    }

    fn serial_number_parser(s: &str) -> Result<(&str, u128), Error> {
        on_text(s, super::serial_number)
    }

    fn timestamp_parser(s: &str) -> Result<(&str, DateTime<FixedOffset>), Error> {
        on_text(s, super::timestamp)
    }

    fn parse_one(s: &str) -> Result<(&str, Value), Error> {
        on_text(s, |i| {
            parse_value_at(i, crate::parsing::Ctx::new(crate::Counting::Quadlets))
        })
    }

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

        let expected_sig = BASE64_URL_SAFE.decode("mdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ==").unwrap();
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
        let str_to_parse = [sai_str, "more"].join("");
        assert_eq!(
            parse_primitive::<SelfAddressing>(&str_to_parse),
            Ok(("more", (SelfAddressing::Blake3_256, digest_raw)))
        );
    }

    #[test]
    fn test_signature() {
        let signature_string =
        "0BC1UBr1QD5TokdcnO_FmnoYsd8rB4_-oaQtk0dfFSSXPcxAu7pSaQIVfkhzckCVmTIgrdxyXS21uZgs7NxoyZAQ";
        let string_to_parse = [signature_string, "more"].join("");

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
