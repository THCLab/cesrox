use std::str::FromStr;

use nom::{character::complete::anychar, combinator::peek, multi::many1, IResult};

use crate::{
    universal_codes::{genus_code, short_universal_group_code, GenusCountCode, UniversalGroupCode}, derivation_code::DerivationCode, group::{codes::GroupCode, parsers::parse_group}, payload::{parse_payload, Payload}, primitives::{codes::PrimitiveCode, parsers::parse_primitive}
};

use super::group::Group;

#[derive(PartialEq, Debug)]
pub enum Value {
    Payload(Payload),
    Primitive(PrimitiveCode, Vec<u8>),
    VersionGenus(GenusCountCode),
    UniversalGroup(UniversalGroupCode, Vec<Value>),
    SpecificGroup(GroupCode, Group),
}

pub fn parse_value(stream: &str) -> IResult<&str, Value> {
    let (rest, selector) = anychar::<_, nom::error::Error<&str>>(stream)?;
    match selector {
        '{' => {
            let (rest, payload) = parse_payload(stream.as_bytes()).unwrap();
            Ok((str::from_utf8(rest).unwrap(), Value::Payload(payload)))
        },
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
                    let (rest, inner_value) = nom::bytes::complete::take(length*4)(rest)?;
                    let (empty_expected, inner_value) = many1(parse_value)(inner_value)?;
                    if !empty_expected.is_empty() {
                        return Err(nom::Err::Error(nom::error::make_error(stream, nom::error::ErrorKind::Many0)));
                    }
                    Ok((rest, Value::UniversalGroup(group_code, inner_value)))
                },
                _ => {
                    // Specific group code
                    let code = GroupCode::from_str(stream).unwrap();
                    let (rest, group) = parse_group(stream.as_bytes()).unwrap();
                    Ok((str::from_utf8(rest).unwrap(), Value::SpecificGroup(code, group)))
                }
            }
        }
        x if x.is_alphanumeric() => {
            // It's primitive
            let (rest, value) = parse_primitive::<PrimitiveCode>(stream.as_bytes()).unwrap();
            Ok((str::from_utf8(rest).unwrap(), Value::Primitive(value.0, value.1)))
        }
        _ => todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        universal_codes::{GenusCountCode, SpecialCountCode, UniversalGroupCode}, group::{codes::GroupCode, Group}, primitives::codes::{
            attached_signature_code::{AttachedSignatureCode, Index}, basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning, PrimitiveCode
        }, value::{parse_value, Value}
    };

    #[test]
    fn test_parse_controller_signatures() {
        let val = parse_value("-KABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let expected_val = Value::SpecificGroup(
            GroupCode::IndexedControllerSignatures(1),
            Group::IndexedControllerSignatures(vec![(
                AttachedSignatureCode {
                    index: Index::BothSame(0),
                    code: SelfSigning::Ed25519Sha512,
                },
                vec![0u8; 64],
            )]),
        );
        assert_eq!(val, Ok(("", expected_val)));

        let val = parse_value("-KACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let expected_val = Value::SpecificGroup(
            GroupCode::IndexedControllerSignatures(2),
            Group::IndexedControllerSignatures(vec![
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
            ]),
        );
        assert_eq!(val, Ok(("", expected_val)));

        let val = parse_value("-KACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAextra data");
        let expected_val = Value::SpecificGroup(
            GroupCode::IndexedControllerSignatures(2),
            Group::IndexedControllerSignatures(vec![
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
            ]),
        );
        assert_eq!(val, Ok(("extra data", expected_val)));

        assert!(parse_value("-KABAA0Q7bqPvenjWXo_YIikMBKOg-pghLKwBi1Plm0PEqdv67L1_c6dq9bll7OFnoLp0a74Nw1cBGdjIPcu-yAllHAw").is_ok());
    }

    #[test]
    fn test_parse_groups() {
        // let attached_str = "-GAC0AAAAAAAAAAAAAAAAAAAAAABEJtQndkvwnMpVGE5oVVbLWSCm-jLviGw1AOOkzBvNwsS0AAAAAAAAAAAAAAAAAAAAAABEJtQndkvwnMpVGE5oVVbLWSCm-jLviGw1AOOkzBvNwsS";
        // let (_rest, attached_sn_dig) = parse_value(attached_str).unwrap();
        // let expected_value = Value::Group(
        //     GroupCode::SealSourceCouples(2),
        //     Group::SourceSealCouples(vec![
        //         (
        //             1,
        //             (
        //                 SelfAddressing::Blake3_256,
        //                 vec![
        //                     155, 80, 157, 217, 47, 194, 115, 41, 84, 97, 57, 161, 85, 91, 45, 100,
        //                     130, 155, 232, 203, 190, 33, 176, 212, 3, 142, 147, 48, 111, 55, 11,
        //                     18,
        //                 ],
        //             ),
        //         ),
        //         (
        //             1,
        //             (
        //                 SelfAddressing::Blake3_256,
        //                 vec![
        //                     155, 80, 157, 217, 47, 194, 115, 41, 84, 97, 57, 161, 85, 91, 45, 100,
        //                     130, 155, 232, 203, 190, 33, 176, 212, 3, 142, 147, 48, 111, 55, 11,
        //                     18,
        //                 ],
        //             ),
        //         ),
        //     ]),
        // );
        // assert_eq!(attached_sn_dig, expected_value);

        // let attached_str = "-FABEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o0AAAAAAAAAAAAAAAAAAAAAAAEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o-AABAABB5IVZOhEfcH4TBQgOCyMgyQrJujtBBjT8K_zTPk0-FLMtTZuBgXV7jnLw6fDe6FWtzshh2HGCL_H_j4i1b9kF";
        // let (_rest, value) = parse_value(attached_str).unwrap();
        // let expected_value = Value::Group(
        //     GroupCode::TransferableIndexedSigGroups(1),
        //     Group::TransIndexedSigGroups(vec![(
        //         (
        //             IdentifierCode::SelfAddressing(SelfAddressing::Blake3_256),
        //             vec![
        //                 160, 188, 211, 206, 105, 193, 44, 51, 47, 5, 6, 206, 31, 135, 172, 74, 5,
        //                 15, 6, 103, 8, 154, 182, 237, 181, 105, 229, 171, 93, 49, 63, 104,
        //             ],
        //         ),
        //         0,
        //         (
        //             SelfAddressing::Blake3_256,
        //             vec![
        //                 160, 188, 211, 206, 105, 193, 44, 51, 47, 5, 6, 206, 31, 135, 172, 74, 5,
        //                 15, 6, 103, 8, 154, 182, 237, 181, 105, 229, 171, 93, 49, 63, 104,
        //             ],
        //         ),
        //         vec![(
        //             AttachedSignatureCode {
        //                 code: SelfSigning::Ed25519Sha512,
        //                 index: Index::BothSame(0),
        //             },
        //             vec![
        //                 65, 228, 133, 89, 58, 17, 31, 112, 126, 19, 5, 8, 14, 11, 35, 32, 201, 10,
        //                 201, 186, 59, 65, 6, 52, 252, 43, 252, 211, 62, 77, 62, 20, 179, 45, 77,
        //                 155, 129, 129, 117, 123, 142, 114, 240, 233, 240, 222, 232, 85, 173, 206,
        //                 200, 97, 216, 113, 130, 47, 241, 255, 143, 136, 181, 111, 217, 5,
        //             ],
        //         )],
        //     )]),
        // );

        // assert_eq!(value, expected_value);

        let attached_str = "-MABBMrwi0a-Zblpqe5Hg7w7iz9JCKnMgWKu_W9w4aNUL64y0BB6cL0DtDVDW26lgjbQu0_D_Pd_6ovBZj6fU-Qjmm7epVs51jEOOwXKbmG4yUvCSN-DQSYSc7HXZRp8CfAw9DQL";
        let (_rest, value) = parse_value(attached_str).unwrap();
        let expected_value = Value::SpecificGroup(
            GroupCode::NontransferableReceiptCouples(1),
            Group::NontransReceiptCouples(vec![(
                (
                    Basic::Ed25519Nontrans,
                    vec![
                        202, 240, 139, 70, 190, 101, 185, 105, 169, 238, 71, 131, 188, 59, 139, 63,
                        73, 8, 169, 204, 129, 98, 174, 253, 111, 112, 225, 163, 84, 47, 174, 50,
                    ],
                ),
                (
                    SelfSigning::Ed25519Sha512,
                    vec![
                        122, 112, 189, 3, 180, 53, 67, 91, 110, 165, 130, 54, 208, 187, 79, 195,
                        252, 247, 127, 234, 139, 193, 102, 62, 159, 83, 228, 35, 154, 110, 222,
                        165, 91, 57, 214, 49, 14, 59, 5, 202, 110, 97, 184, 201, 75, 194, 72, 223,
                        131, 65, 38, 18, 115, 177, 215, 101, 26, 124, 9, 240, 48, 244, 52, 11,
                    ],
                ),
            )]),
        );

        assert_eq!(value, expected_value);

        let cesr_attachment = "-KABAAB6P97kZ3al3V3z3VstRtHRPeOrotuqZZUgBl2yHzgpGyOjAXYGinVqWLAMhdmQ089FTSAzqSTBmJzI8RvIezsJ";
        let (_rest, value) = parse_value(cesr_attachment).unwrap();
        let expected_value = Value::SpecificGroup(
            GroupCode::IndexedControllerSignatures(1),
            Group::IndexedControllerSignatures(vec![(
                AttachedSignatureCode {
                    code: SelfSigning::Ed25519Sha512,
                    index: Index::BothSame(0),
                },
                vec![
                    122, 63, 222, 228, 103, 118, 165, 221, 93, 243, 221, 91, 45, 70, 209, 209, 61,
                    227, 171, 162, 219, 170, 101, 149, 32, 6, 93, 178, 31, 56, 41, 27, 35, 163, 1,
                    118, 6, 138, 117, 106, 88, 176, 12, 133, 217, 144, 211, 207, 69, 77, 32, 51,
                    169, 36, 193, 152, 156, 200, 241, 27, 200, 123, 59, 9,
                ],
            )]),
        );

        assert_eq!(value, expected_value);

        // TODO
        // let cesr_attachment = "-VAj-HABEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3-AABAAB6P97kZ3al3V3z3VstRtHRPeOrotuqZZUgBl2yHzgpGyOjAXYGinVqWLAMhdmQ089FTSAzqSTBmJzI8RvIezsJ";
        // let (rest, att) = attachment(cesr_attachment.as_bytes()).unwrap();
        // assert!(matches!(att, Attachment::Frame(_)));
        // assert!(rest.is_empty());
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

    }

      #[test]
    fn test_parse_nested() {
        let (rest, value) = parse_value("-AAX-KABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        match value {
            Value::UniversalGroup(UniversalGroupCode::Special { code, quadlets: length }, values) => {
                assert_eq!(code, SpecialCountCode::GenericPipeline);
                assert_eq!(length, 23);
                assert_eq!(values.len(), 1);
                assert_eq!(values[0], Value::SpecificGroup(
                    GroupCode::IndexedControllerSignatures(1),
                    Group::IndexedControllerSignatures(vec![(
                        AttachedSignatureCode {
                            index: Index::BothSame(0),
                            code: SelfSigning::Ed25519Sha512,
                        },
                        vec![0u8; 64],
                    )]),
                ));
            }
            _ => panic!("Unexpected element type"),
        };
        assert!(rest.is_empty());
    }

    #[test]
    fn test_parse_stream() {
        let (rest, value) = nom::multi::many0(parse_value)(r#"{"hello":"world"}-AAX-KABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"#).unwrap();
        dbg!(&value);
        assert!(rest.is_empty());
        assert_eq!(value.len(), 2);
        assert!(matches!(&value[0], Value::Payload(_)));
        if let Value::UniversalGroup(UniversalGroupCode::Special { code, quadlets }, contents) = &value[1] {
            matches!(code, SpecialCountCode::GenericPipeline);
            assert_eq!(contents.len(), 1);
            matches!(&contents[0], Value::SpecificGroup(
                GroupCode::IndexedControllerSignatures(1),
                Group::IndexedControllerSignatures(_)
            ));
        } else {
            panic!("Unexpected element type");
        }
    }

     #[test]
    fn test_parse_primitive() {
        let sai_str = "ENmwqnqVxonf_bNZ0hMipOJJY25dxlC8eSY5BbyMCfLJ";
        let (rest, value) = parse_value(sai_str).unwrap();
        match value {
            Value::Primitive(PrimitiveCode::SelfAddressing(_), data) => {
                assert_eq!(data.len(), 32);
                assert_eq!(data, vec![217, 176, 170, 122, 149, 198, 137, 223, 253, 179, 89, 210, 19, 34, 164, 226, 73, 99, 110, 93, 198, 80, 188, 121, 38, 57, 5, 188, 140, 9, 242, 201]);
            },
            _ => unreachable!()
        }
       
        assert_eq!(rest, "");
        // println!("Parsed value: {:?}", value.to);
    }
}
