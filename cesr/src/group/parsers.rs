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
    conversion::check_first_three_bits,
    primitives::{
        codes::{
            attached_signature_code::AttachedSignatureCode, basic::Basic,
            self_addressing::SelfAddressing, self_signing::SelfSigning,
        },
        parsers::{anchoring_event_seal, parse_primitive, serial_number_parser, timestamp_parser},
    },
};

use super::{codes::GroupCode, Group};

pub fn group_code(s: &[u8]) -> nom::IResult<&[u8], GroupCode> {
    let (rest, payload_type) = take(4u8)(s)?;
    let Ok(group_code) = GroupCode::from_str(std::str::from_utf8(payload_type).unwrap()) else {
        return Err(nom::Err::Error(make_error(s, ErrorKind::IsNot)));
    };
    Ok((rest, group_code))
}

pub fn parse_group(stream: &[u8]) -> nom::IResult<&[u8], Group> {
    let first_byte = stream
        .first()
        .ok_or(nom::Err::Error(make_error(stream, ErrorKind::Eof)))?;
    let first_three_bits = check_first_three_bits(first_byte);
    if !(first_three_bits == 0b111 || first_three_bits == 0b001 || first_three_bits == 0b010) {
        // It's not attachment
        return Err(nom::Err::Error(make_error(stream, ErrorKind::IsNot)));
    }

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
    })
}

#[test]
pub fn test_parse_group() {
    use crate::primitives::Timestamp;
    let group_str = "-OAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2022-10-25T12c04c30d175309p00c00";
    let (_rest, group) = parse_group(group_str.as_bytes()).unwrap();
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
    let (_rest, attached_material) = parse_group(attached_str.as_bytes()).unwrap();
    let expected_path = MaterialPath::to_path("-a".into());
    if let Group::PathedMaterialQuadruplet(material_path, groups) = attached_material {
        assert_eq!(material_path, expected_path);
        assert_eq!(groups.len(), 1)
    };
}
