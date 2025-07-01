use std::fmt::Display;

use nom::{character::complete::anychar, combinator::peek, multi::many1, IResult};

#[cfg(feature = "cesr-proof")]
use crate::cesr_proof::{parsers::material_path, MaterialPath};

use crate::{
    conversion::from_bytes_to_text,
    derivation_code::DerivationCode,
    group::parsers::parse_group,
    payload::{parse_payload, Payload},
    primitives::{
        codes::{PrimitiveCode, TagCode},
        parsers::parse_primitive,
    },
    universal_codes::{genus_code, short_universal_group_code, GenusCountCode, UniversalGroupCode},
};

use super::group::Group;

#[derive(PartialEq, Debug)]
pub enum Value {
    Payload(Payload),
    Primitive(PrimitiveCode, Vec<u8>),
    Tag(TagCode),
    VersionGenus(GenusCountCode),
    UniversalGroup(UniversalGroupCode, Vec<Value>),
    SpecificGroup(Group),

    #[cfg(feature = "cesr-proof")]
    Base64String(MaterialPath),
}

pub fn parse_value(stream: &str) -> IResult<&str, Value> {
    let (rest, selector) = anychar::<_, nom::error::Error<&str>>(stream)?;
    match selector {
        '{' => {
            let (rest, payload) = parse_payload(stream.as_bytes()).map_err(|e| {
                e.map(|e| {
                    let rest = str::from_utf8(e.input).unwrap();
                    nom::error::make_error(rest, e.code)
                })
            })?;
            Ok((str::from_utf8(rest).unwrap(), Value::Payload(payload)))
        }
        '-' => {
            // It's group
            let (_, selector) = peek(anychar)(rest)?;
            match selector {
                '_' => {
                    // Protocol Version Genus
                    let (rest, genus) = genus_code(rest)?;
                    Ok((rest, Value::VersionGenus(genus)))
                }
                'A' | 'B' | 'C' => {
                    // Universal group code
                    let (rest, group_code) = short_universal_group_code(rest)?;
                    let length = group_code.value_size();
                    let (rest, inner_value) = nom::bytes::complete::take(length * 4)(rest)?;
                    let (empty_expected, inner_value) = many1(parse_value)(inner_value)?;
                    if !empty_expected.is_empty() {
                        return Err(nom::Err::Error(nom::error::make_error(
                            stream,
                            nom::error::ErrorKind::Many0,
                        )));
                    }
                    Ok((rest, Value::UniversalGroup(group_code, inner_value)))
                }

                _ => {
                    // Specific group code
                    let (rest, group) = parse_group(stream)?;
                    Ok((rest, Value::SpecificGroup(group)))
                }
            }
        }
        #[cfg(feature = "cesr-proof")]
        '4' | '5' | '6' => {
            let (rest, path) = material_path(stream)?;
            Ok((rest, Value::Base64String(path)))
        }
        x if x.is_alphanumeric() => {
            // It's primitive
            let (rest, value) = parse_primitive::<PrimitiveCode>(stream)?;
            match &value.0 {
                PrimitiveCode::Tag(tag_code) => Ok((rest, Value::Tag(tag_code.clone()))),
                _ => Ok((rest, Value::Primitive(value.0, value.1))),
            }
        }
        _ => todo!(),
    }
}

impl Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Value::Payload(Payload::JSON(json)) => String::from_utf8(json.clone()).unwrap(),
            Value::Primitive(primitive_code, value) => {
                let dc = primitive_code.to_str();
                let lead_bytes = if dc.len() % 4 != 0 { dc.len() % 4 } else { 0 };
                // replace lead bytes with code
                let derivative_text = from_bytes_to_text(value)[lead_bytes..].to_string();
                [dc, derivative_text].join("")
            }
            Value::VersionGenus(genus_count_code) => format!("-{}", genus_count_code),
            Value::UniversalGroup(universal_group_code, values) => format!(
                "-{}{}",
                universal_group_code,
                values.iter().map(|v| v.to_string()).collect::<String>()
            ),
            Value::SpecificGroup(group) => group.to_cesr_str(),
            Value::Tag(tag_code) => tag_code.to_str(),
            #[cfg(feature = "cesr-proof")]
            Value::Base64String(path) => path.to_cesr(),
            _ => todo!(),
        };
        write!(f, "{}", text)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        group::Group,
        primitives::{
            codes::{
                attached_signature_code::{AttachedSignatureCode, Index},
                basic::Basic,
                self_addressing::SelfAddressing,
                self_signing::SelfSigning,
                PrimitiveCode,
            },
            IdentifierCode,
        },
        universal_codes::{GenusCountCode, SpecialCountCode, UniversalGroupCode},
        value::{parse_value, Value},
    };

    #[test]
    fn test_parse_controller_signatures() {
        let stream = "-KABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let (_, val) = parse_value(stream).unwrap();
        let expected_val = Value::SpecificGroup(Group::IndexedControllerSignatures(vec![(
            AttachedSignatureCode {
                index: Index::BothSame(0),
                code: SelfSigning::Ed25519Sha512,
            },
            vec![0u8; 64],
        )]));
        assert_eq!(val, expected_val);
        assert_eq!(val.to_string(), stream);

        let stream = "-KACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let (_rest, val) = parse_value(stream).unwrap();
        let expected_val = Value::SpecificGroup(Group::IndexedControllerSignatures(vec![
            (
                AttachedSignatureCode {
                    index: Index::BothSame(0),
                    code: SelfSigning::Ed25519Sha512,
                },
                vec![0u8; 64],
            ),
            (
                AttachedSignatureCode {
                    index: Index::Dual(0, 2),
                    code: SelfSigning::Ed448,
                },
                vec![0u8; 114],
            ),
        ]));
        assert_eq!(val, expected_val);
        assert_eq!(val.to_string(), stream);

        let stream_with_extra_data = "-KACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAextra data";
        let (rest, val) = parse_value(stream_with_extra_data).unwrap();
        let expected_val = Value::SpecificGroup(Group::IndexedControllerSignatures(vec![
            (
                AttachedSignatureCode {
                    index: Index::BothSame(0),
                    code: SelfSigning::Ed25519Sha512,
                },
                vec![0u8; 64],
            ),
            (
                AttachedSignatureCode {
                    index: Index::Dual(0, 2),
                    code: SelfSigning::Ed448,
                },
                vec![0u8; 114],
            ),
        ]));
        assert_eq!(rest, "extra data");
        assert_eq!(val, expected_val);
        assert_eq!(
            val.to_string(),
            stream_with_extra_data[..stream_with_extra_data.len() - 10]
        );

        assert!(parse_value("-KABAA0Q7bqPvenjWXo_YIikMBKOg-pghLKwBi1Plm0PEqdv67L1_c6dq9bll7OFnoLp0a74Nw1cBGdjIPcu-yAllHAw").is_ok());
    }

    #[test]
    fn test_parse_groups() {
        let attached_str = "-TAC0AAAAAAAAAAAAAAAAAAAAAABEJtQndkvwnMpVGE5oVVbLWSCm-jLviGw1AOOkzBvNwsS0AAAAAAAAAAAAAAAAAAAAAABEJtQndkvwnMpVGE5oVVbLWSCm-jLviGw1AOOkzBvNwsS";
        let (_rest, attached_sn_dig) = parse_value(attached_str).unwrap();
        let expected_value = Value::SpecificGroup(Group::SourceSealCouples(vec![
            (
                1,
                (
                    SelfAddressing::Blake3_256,
                    vec![
                        155, 80, 157, 217, 47, 194, 115, 41, 84, 97, 57, 161, 85, 91, 45, 100, 130,
                        155, 232, 203, 190, 33, 176, 212, 3, 142, 147, 48, 111, 55, 11, 18,
                    ],
                ),
            ),
            (
                1,
                (
                    SelfAddressing::Blake3_256,
                    vec![
                        155, 80, 157, 217, 47, 194, 115, 41, 84, 97, 57, 161, 85, 91, 45, 100, 130,
                        155, 232, 203, 190, 33, 176, 212, 3, 142, 147, 48, 111, 55, 11, 18,
                    ],
                ),
            ),
        ]));
        assert_eq!(attached_sn_dig, expected_value);
        assert_eq!(attached_sn_dig.to_string(), attached_str);

        let attached_str = "-SABEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o0AAAAAAAAAAAAAAAAAAAAAAAEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o-KABAABB5IVZOhEfcH4TBQgOCyMgyQrJujtBBjT8K_zTPk0-FLMtTZuBgXV7jnLw6fDe6FWtzshh2HGCL_H_j4i1b9kF";
        let (rest, value) = parse_value(attached_str).unwrap();
        let expected_value_1 = Value::SpecificGroup(Group::AnchoringSeals(vec![(
            (
                IdentifierCode::SelfAddressing(SelfAddressing::Blake3_256),
                vec![
                    160, 188, 211, 206, 105, 193, 44, 51, 47, 5, 6, 206, 31, 135, 172, 74, 5, 15,
                    6, 103, 8, 154, 182, 237, 181, 105, 229, 171, 93, 49, 63, 104,
                ],
            ),
            0,
            (
                SelfAddressing::Blake3_256,
                vec![
                    160, 188, 211, 206, 105, 193, 44, 51, 47, 5, 6, 206, 31, 135, 172, 74, 5, 15,
                    6, 103, 8, 154, 182, 237, 181, 105, 229, 171, 93, 49, 63, 104,
                ],
            ),
        )]));
        assert_eq!(value, expected_value_1);
        assert_eq!(value.to_string(), attached_str[0..116]);

        let (_rest, value) = parse_value(rest).unwrap();

        let expected_value_2 = Value::SpecificGroup(Group::IndexedControllerSignatures(vec![(
            AttachedSignatureCode {
                code: SelfSigning::Ed25519Sha512,
                index: Index::BothSame(0),
            },
            vec![
                65, 228, 133, 89, 58, 17, 31, 112, 126, 19, 5, 8, 14, 11, 35, 32, 201, 10, 201,
                186, 59, 65, 6, 52, 252, 43, 252, 211, 62, 77, 62, 20, 179, 45, 77, 155, 129, 129,
                117, 123, 142, 114, 240, 233, 240, 222, 232, 85, 173, 206, 200, 97, 216, 113, 130,
                47, 241, 255, 143, 136, 181, 111, 217, 5,
            ],
        )]));

        assert_eq!(value, expected_value_2);
        assert_eq!(value.to_string(), attached_str[116..]);

        let attached_str = "-MABBMrwi0a-Zblpqe5Hg7w7iz9JCKnMgWKu_W9w4aNUL64y0BB6cL0DtDVDW26lgjbQu0_D_Pd_6ovBZj6fU-Qjmm7epVs51jEOOwXKbmG4yUvCSN-DQSYSc7HXZRp8CfAw9DQL";
        let (_rest, value) = parse_value(attached_str).unwrap();
        let expected_value = Value::SpecificGroup(Group::NontransReceiptCouples(vec![(
            (
                Basic::Ed25519Nontrans,
                vec![
                    202, 240, 139, 70, 190, 101, 185, 105, 169, 238, 71, 131, 188, 59, 139, 63, 73,
                    8, 169, 204, 129, 98, 174, 253, 111, 112, 225, 163, 84, 47, 174, 50,
                ],
            ),
            (
                SelfSigning::Ed25519Sha512,
                vec![
                    122, 112, 189, 3, 180, 53, 67, 91, 110, 165, 130, 54, 208, 187, 79, 195, 252,
                    247, 127, 234, 139, 193, 102, 62, 159, 83, 228, 35, 154, 110, 222, 165, 91, 57,
                    214, 49, 14, 59, 5, 202, 110, 97, 184, 201, 75, 194, 72, 223, 131, 65, 38, 18,
                    115, 177, 215, 101, 26, 124, 9, 240, 48, 244, 52, 11,
                ],
            ),
        )]));

        assert_eq!(value, expected_value);
        assert_eq!(value.to_string(), attached_str);

        let cesr_attachment = "-KABAAB6P97kZ3al3V3z3VstRtHRPeOrotuqZZUgBl2yHzgpGyOjAXYGinVqWLAMhdmQ089FTSAzqSTBmJzI8RvIezsJ";
        let (_rest, value) = parse_value(cesr_attachment).unwrap();
        let expected_value = Value::SpecificGroup(Group::IndexedControllerSignatures(vec![(
            AttachedSignatureCode {
                code: SelfSigning::Ed25519Sha512,
                index: Index::BothSame(0),
            },
            vec![
                122, 63, 222, 228, 103, 118, 165, 221, 93, 243, 221, 91, 45, 70, 209, 209, 61, 227,
                171, 162, 219, 170, 101, 149, 32, 6, 93, 178, 31, 56, 41, 27, 35, 163, 1, 118, 6,
                138, 117, 106, 88, 176, 12, 133, 217, 144, 211, 207, 69, 77, 32, 51, 169, 36, 193,
                152, 156, 200, 241, 27, 200, 123, 59, 9,
            ],
        )]));

        assert_eq!(value, expected_value);
        assert_eq!(value.to_string(), cesr_attachment);
    }

    #[test]
    fn test_version_parse() {
        let input = "-_AAABAAabcdef";
        let (rest, value) = parse_value(input).unwrap();

        assert_eq!(rest, "abcdef");
        match value {
            Value::VersionGenus(GenusCountCode::Keri { minor, major }) => {
                assert_eq!(minor, 0);
                assert_eq!(major, 1);
            }
            _ => panic!("Unexpected element type"),
        }
        assert_eq!(value.to_string(), input[0..8]);
    }

    #[test]
    fn test_parse_nested() {
        let input = "-AAX-KABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let (rest, value) = parse_value(input).unwrap();
        match &value {
            Value::UniversalGroup(
                UniversalGroupCode::Special {
                    code,
                    quadlets: length,
                },
                values,
            ) => {
                assert_eq!(code, &SpecialCountCode::GenericPipeline);
                assert_eq!(length, &23);
                assert_eq!(values.len(), 1);
                assert_eq!(
                    values[0],
                    Value::SpecificGroup(Group::IndexedControllerSignatures(vec![(
                        AttachedSignatureCode {
                            index: Index::BothSame(0),
                            code: SelfSigning::Ed25519Sha512,
                        },
                        vec![0u8; 64],
                    )]),)
                );
            }
            _ => panic!("Unexpected element type"),
        };
        assert!(rest.is_empty());
        assert_eq!(value.to_string(), input);
    }

    #[test]
    fn test_parse_stream() {
        let input = r#"{"hello":"world"}-AAX-KABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"#;
        let (rest, value) = nom::multi::many0(parse_value)(input).unwrap();
        assert!(rest.is_empty());
        assert_eq!(value.len(), 2);
        assert!(matches!(&value[0], Value::Payload(_)));
        if let Value::UniversalGroup(UniversalGroupCode::Special { code, quadlets: _ }, contents) =
            &value[1]
        {
            matches!(code, SpecialCountCode::GenericPipeline);
            assert_eq!(contents.len(), 1);
            matches!(
                &contents[0],
                Value::SpecificGroup(Group::IndexedControllerSignatures(_))
            );
        } else {
            panic!("Unexpected element type");
        }
        assert_eq!(
            value
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(""),
            input
        );
    }

    #[test]
    fn test_parse_primitive() {
        let sai_str = "ENmwqnqVxonf_bNZ0hMipOJJY25dxlC8eSY5BbyMCfLJ";
        let (rest, value) = parse_value(sai_str).unwrap();
        match &value {
            Value::Primitive(PrimitiveCode::SelfAddressing(_), data) => {
                assert_eq!(data.len(), 32);
                assert_eq!(
                    data,
                    &[
                        217, 176, 170, 122, 149, 198, 137, 223, 253, 179, 89, 210, 19, 34, 164,
                        226, 73, 99, 110, 93, 198, 80, 188, 121, 38, 57, 5, 188, 140, 9, 242, 201
                    ]
                );
            }
            _ => unreachable!(),
        }

        assert_eq!(rest, "");
        assert_eq!(value.to_string(), sai_str);
    }
}
