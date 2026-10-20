use std::str::FromStr;

use nom::{
    bytes::complete::take,
    multi::{count, many0},
    Parser,
};

use crate::{
    error::Error,
    parsing::{ascii, code_error, error, failure, finish, PResult},
    primitives::{
        codes::{
            attached_signature_code::AttachedSignatureCode, basic::Basic,
            self_addressing::SelfAddressing, self_signing::SelfSigning,
        },
        parsers::{anchoring_event_seal, identifier, primitive, serial_number, timestamp},
    },
    value::{parse_value_at, MAX_NESTING},
    Parsed,
};

use super::{codes::GroupCode, Group};

/// Parses one attachment group at the start of `input`. Returns the group
/// and the rest of the input.
pub fn parse_group(input: &[u8]) -> Parsed<'_, Group> {
    finish(input, parse_group_at(input, 0))
}

/// Parse a single `(identifier, indexed_signatures)` entry inside a
/// `TransLastIdxSigGroups` (`-Y`) group: the identifier prefix followed by an
/// inner `IndexedControllerSignatures` (`-K`) group whose payload becomes the
/// indexed signatures.
fn trans_last_entry(
    input: &[u8],
    depth: usize,
) -> PResult<
    '_,
    (
        crate::primitives::Identifier,
        Vec<crate::primitives::IndexedSignature>,
    ),
> {
    let (rest, id) = identifier(input)?;
    let (rest, inner) = parse_group_at(rest, depth + 1)?;
    match inner {
        Group::IndexedControllerSignatures(sigs) => Ok((rest, (id, sigs))),
        _ => error(
            input,
            Error::Invalid("expected indexed controller signatures".into()),
        ),
    }
}

pub(crate) fn group_code(input: &[u8]) -> PResult<'_, GroupCode> {
    match GroupCode::from_str(ascii(input)) {
        Ok(code) => {
            let (rest, _) = take(4u8)(input)?;
            Ok((rest, code))
        }
        Err(e) => error(input, code_error(input, e)),
    }
}

/// Parses one group found `depth` groups deep; see [`MAX_NESTING`].
pub(crate) fn parse_group_at(stream: &[u8], depth: usize) -> PResult<'_, Group> {
    if depth > MAX_NESTING {
        return failure(stream, Error::NestingTooDeep);
    }
    // let first_byte = stream
    //     .first()
    //     .ok_or(nom::Err::Error(make_error(stream, ErrorKind::Eof)))?;
    // let first_three_bits = check_first_three_bits(first_byte);
    // if !(first_three_bits == 0b111 || first_three_bits == 0b001 || first_three_bits == 0b010) {
    //     // It's not attachment
    //     return Err(nom::Err::Error(make_error(stream, ErrorKind::IsNot)));
    // }

    let (rest, group_code) = group_code(stream)?;
    Ok(match group_code {
        GroupCode::IndexedControllerSignatures(n) => {
            let (rest, signatures) =
                count(primitive::<AttachedSignatureCode>, n as usize).parse(rest)?;
            (rest, Group::IndexedControllerSignatures(signatures))
        }
        GroupCode::IndexedWitnessSignatures(n) => {
            let (rest, signatures) =
                count(primitive::<AttachedSignatureCode>, n as usize).parse(rest)?;
            (rest, Group::IndexedWitnessSignatures(signatures))
        }
        GroupCode::NontransferableReceiptCouples(n) => {
            let (rest, couple) =
                count((primitive::<Basic>, primitive::<SelfSigning>), n as usize).parse(rest)?;
            (rest, Group::NontransReceiptCouples(couple))
        }
        GroupCode::SealSourceCouples(n) => {
            let (rest, couple) =
                count((serial_number, primitive::<SelfAddressing>), n as usize).parse(rest)?;
            (rest, Group::SourceSealCouples(couple))
        }
        GroupCode::FirstSeenReplyCouples(n) => {
            let (rest, couple) = count((serial_number, timestamp), n as usize).parse(rest)?;
            (rest, Group::FirstSeenReplyCouples(couple))
        }
        GroupCode::AnchoringEventSeals(n) => {
            let (rest, quadruple) = count(anchoring_event_seal, n as usize).parse(rest)?;
            (rest, Group::AnchoringSeals(quadruple))
        }
        GroupCode::TransLastIdxSigGroups(n) => {
            let (rest, entries) = count(|s| trans_last_entry(s, depth), n as usize).parse(rest)?;
            (rest, Group::TransLastIdxSigGroups(entries))
        }
        #[cfg(feature = "cesr-proof")]
        GroupCode::PathedMaterialQuadruple(n) => {
            // n * 4 is all path and attachments length (?)
            match nom::bytes::complete::take(n * 4)(rest) {
                Ok((rest, total)) => {
                    use crate::variable_length::{
                        variable_length_value, SmallVariableLengthCode, VariableLengthCode,
                    };
                    let (extra, mp) = variable_length_value(total)?;
                    let material_path = match mp.code() {
                        VariableLengthCode::Small {
                            code: SmallVariableLengthCode::Base64String,
                            lb,
                            length: _,
                        } => {
                            use crate::{cesr_proof::MaterialPath, conversion::from_bytes_to_text};

                            let value = from_bytes_to_text(mp.value());
                            MaterialPath::new(lb.clone(), value)
                        }
                        _ => {
                            return error(total, Error::Invalid("expected a material path".into()))
                        }
                    };
                    let (_extra, attachment) =
                        many0(|s| parse_group_at(s, depth + 1)).parse(extra)?;

                    Ok((
                        rest,
                        Group::PathedMaterialQuadruplet(material_path, attachment),
                    ))
                }
                Err(e) => Err(e),
            }?
        }
        GroupCode::TSPPayload(n) => match nom::bytes::complete::take(n * 4)(rest) {
            Ok((main_rest, total)) => {
                let (rest, values) = many0(|s| parse_value_at(s, depth + 1)).parse(total)?;
                if !rest.is_empty() {
                    return error(total, Error::Invalid("unparsed data in TSP payload".into()));
                }
                Ok((main_rest, Group::TSPPayload(values)))
            }
            Err(e) => Err(e),
        }?,
    })
}

#[cfg(test)]
mod tests {
    use super::parse_group;
    use crate::{
        group::Group,
        parse_value,
        primitives::{
            codes::{attached_signature_code::AttachedSignatureCode, TagCode},
            parse_primitive,
            parsers::identifier,
        },
        value::Value,
    };

    #[test]
    fn test_trans_last_idx_sig_groups_roundtrip() {
        let id_str = "EIgR-AyPKJLG3l7dzk-KWpMpB0lI7l5fwQxk7tOlloEA";
        let sig_str =
            "AADmMIvtVLCm62rgeBweQms4mhJxuQBAlWWBOiXiQLiN6qJsMoi8_afcOtRL86CXFjuxOVmR1tnxY3Iygs-5M28D";

        let (_, id) = identifier(id_str.as_bytes()).unwrap();
        let ((sig_code, sig), _) =
            parse_primitive::<AttachedSignatureCode>(sig_str.as_bytes()).unwrap();
        let isig: crate::primitives::IndexedSignature = (sig_code, sig);

        let group = Group::TransLastIdxSigGroups(vec![(id, vec![isig])]);
        let encoded = group.to_cesr_str();
        assert!(encoded.starts_with("-YAB"), "encoded = {encoded}");

        let (parsed, rest) = parse_group(encoded.as_bytes()).unwrap();
        assert!(rest.is_empty(), "leftover bytes: {rest:?}");
        assert_eq!(parsed, group);
    }

    #[test]
    fn test_parse_group() {
        use crate::primitives::Timestamp;
        let group_str = "-OAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2022-10-25T12c04c30d175309p00c00";
        let (group, _rest) = parse_group(group_str.as_bytes()).unwrap();
        let expected = (
            0,
            "2022-10-25T12:04:30.175309+00:00"
                .parse::<Timestamp>()
                .unwrap(),
        );
        assert_eq!(group, Group::FirstSeenReplyCouples(vec![expected]));
    }

    #[cfg(feature = "cesr-proof")]
    #[test]
    fn test_pathed_material() {
        use crate::cesr_proof::MaterialPath;

        let attached_str = "-PAZ5AABAA-a-KABAAFjjD99-xy7J0LGmCkSE_zYceED5uPF4q7l8J23nNQ64U-oWWulHI5dh3cFDWT4eICuEQCALdh8BO5ps-qx0qBA";
        let (attached_material, _rest) = parse_group(attached_str.as_bytes()).unwrap();
        let expected_path = MaterialPath::create_from_str("-a".into());
        if let Group::PathedMaterialQuadruplet(material_path, groups) = attached_material {
            assert_eq!(material_path, expected_path);
            assert_eq!(groups.len(), 1)
        };
    }

    #[test]
    fn test_tsp_payload() {
        let msg_type = "XRFI";
        let id = "ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux";
        let said = "ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux";
        let nounce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let relation_dig = "ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux";
        let ((tag, _), _) = parse_primitive::<TagCode>(msg_type.as_bytes()).unwrap();

        let tsp_payload = vec![
            Value::Tag(tag),
            parse_value(said.as_bytes()).unwrap().0,
            parse_value(nounce.as_bytes()).unwrap().0,
            parse_value(relation_dig.as_bytes()).unwrap().0,
            parse_value(id.as_bytes()).unwrap().0,
        ];

        let expected_group = "-ZAtXRFIELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-uxAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-uxELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux";

        let group = Group::TSPPayload(tsp_payload);
        assert_eq!(group.to_cesr_str(), expected_group);

        let (value, rest) = parse_value(expected_group.as_bytes()).unwrap();
        assert!(rest.is_empty());
        match value {
            Value::SpecificGroup(parsed_group) => {
                assert_eq!(parsed_group, group);
            }
            _ => panic!("Expected a Group value"),
        }
    }
}
