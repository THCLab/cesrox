use std::str::FromStr;

use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    multi::{count, many0},
    sequence::tuple,
};

#[cfg(feature = "cesr-proof")]
use crate::cesr_proof::parsers::material_path;
use crate::{
    primitives::{
        codes::{
            attached_signature_code::AttachedSignatureCode, basic::Basic,
            self_addressing::SelfAddressing, self_signing::SelfSigning,
        },
        parsers::{anchoring_event_seal, parse_primitive, serial_number_parser, timestamp_parser},
    },
    value::parse_value,
};

use super::{codes::GroupCode, Group};

pub fn group_code(s: &str) -> nom::IResult<&str, GroupCode> {
    let (rest, payload_type) = take(4u8)(s)?;
    let Ok(group_code) = GroupCode::from_str(payload_type) else {
        return Err(nom::Err::Error(make_error(s, ErrorKind::IsNot)));
    };
    Ok((rest, group_code))
}

pub fn parse_group(stream: &str) -> nom::IResult<&str, Group> {
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
                count(parse_primitive::<AttachedSignatureCode>, n as usize)(rest)?;
            (rest, Group::IndexedControllerSignatures(signatures))
        }
        GroupCode::IndexedWitnessSignatures(n) => {
            let (rest, signatures) =
                count(parse_primitive::<AttachedSignatureCode>, n as usize)(rest)?;
            (rest, Group::IndexedWitnessSignatures(signatures))
        }
        GroupCode::NontransferableReceiptCouples(n) => {
            let (rest, couple) = count(
                tuple((parse_primitive::<Basic>, parse_primitive::<SelfSigning>)),
                n as usize,
            )(rest)?;
            (rest, Group::NontransReceiptCouples(couple))
        }
        GroupCode::SealSourceCouples(n) => {
            let (rest, couple) = count(
                tuple((serial_number_parser, parse_primitive::<SelfAddressing>)),
                n as usize,
            )(rest)?;
            (rest, Group::SourceSealCouples(couple))
        }
        GroupCode::FirstSeenReplyCouples(n) => {
            let (rest, couple) =
                count(tuple((serial_number_parser, timestamp_parser)), n as usize)(rest)?;
            (rest, Group::FirstSeenReplyCouples(couple))
        }
        GroupCode::AnchoringEventSeals(n) => {
            let (rest, quadruple) = count(anchoring_event_seal, n as usize)(rest)?;
            (rest, Group::AnchoringSeals(quadruple))
        }
        #[cfg(feature = "cesr-proof")]
        GroupCode::PathedMaterialQuadruple(n) => {
            // n * 4 is all path and attachments length (?)
            match nom::bytes::complete::take(n * 4)(rest) {
                Ok((rest, total)) => {
                    let (extra, mp) = material_path(total)?;
                    let (_extra, attachment) = many0(parse_group)(extra)?;

                    Ok((rest, Group::PathedMaterialQuadruplet(mp, attachment)))
                }
                Err(e) => Err(e),
            }?
        }
        GroupCode::TSPPayload(n) => match nom::bytes::complete::take(n * 4)(rest) {
            Ok((main_rest, total)) => {
                let (rest, values) = many0(parse_value)(total)?;
                if !rest.is_empty() {
                    return Err(nom::Err::Error(make_error(total, ErrorKind::Many0)));
                }
                Ok((main_rest, Group::TSPPayload(values)))
            }
            Err(e) => Err(e),
        }?,
    })
}

#[test]
pub fn test_parse_group() {
    use crate::primitives::Timestamp;
    let group_str = "-OAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2022-10-25T12c04c30d175309p00c00";
    let (_rest, group) = parse_group(group_str).unwrap();
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
    let (_rest, attached_material) = parse_group(attached_str).unwrap();
    let expected_path = MaterialPath::to_path("-a".into());
    if let Group::PathedMaterialQuadruplet(material_path, groups) = attached_material {
        assert_eq!(material_path, expected_path);
        assert_eq!(groups.len(), 1)
    };
}

#[cfg(test)]
mod tests {
    use crate::{
        group::Group,
        primitives::{codes::TagCode, parsers::parse_primitive},
        value::{parse_value, Value},
    };

    #[test]
    fn test_tsp_payload() {
        let msg_type = "XRFI";
        let id = "ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux";
        let said = "ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux";
        let nounce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let relation_dig = "ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux";
        let (tag, _) = parse_primitive::<TagCode>(&msg_type).unwrap().1;

        let tsp_payload = vec![
            Value::Tag(tag),
            parse_value(said).unwrap().1,
            parse_value(nounce).unwrap().1,
            parse_value(relation_dig).unwrap().1,
            parse_value(id).unwrap().1,
        ];

        let expected_group = "-ZAtXRFIELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-uxAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-uxELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux";

        let group = Group::TSPPayload(tsp_payload);
        assert_eq!(group.to_cesr_str(), expected_group);

        let (rest, value) = parse_value(expected_group).unwrap();
        assert!(rest.is_empty());
        match value {
            crate::value::Value::SpecificGroup(parsed_group) => {
                assert_eq!(parsed_group, group);
            }
            _ => panic!("Expected a Group value"),
        }
    }
}
