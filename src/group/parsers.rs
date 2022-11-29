use std::{num::NonZeroUsize, str::FromStr};

use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    multi::{count, many0},
    sequence::tuple,
    Needed,
};



#[cfg(feature = "cesr-proof")]
use crate::path::parsers::material_path;
use crate::primitives::{codes::{attached_signature_code::AttachedSignatureCode, self_signing::SelfSigning, basic::Basic, self_addressing::SelfAddressing}, parsers::{parse_primitive, serial_number_parser, transferable_quadruple, timestamp_parser, identifier_signature_pair}};

use super::{codes::GroupCode, Group};

pub fn group_code(s: &[u8]) -> nom::IResult<&[u8], GroupCode> {
    let (rest, payload_type) = take(4u8)(s)?;
    let Ok(group_code) = GroupCode::from_str(std::str::from_utf8(payload_type).unwrap()) else {return Err(nom::Err::Error(make_error(s, ErrorKind::IsNot)))};
    Ok((rest, group_code))
}

pub fn parse_group(stream: &[u8]) -> nom::IResult<&[u8], Group> {
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
            (rest, Group::NontransferableReceiptCouples(couple))
        }
        GroupCode::SealSourceCouples(n) => {
            let (rest, couple) = count(
                tuple((serial_number_parser, parse_primitive::<SelfAddressing>)),
                n as usize,
            )(rest)
            .unwrap();
            (rest, Group::SourceSealCouples(couple))
        }
        GroupCode::FirstSeenReplyCouples(n) => {
            let (rest, couple) =
                count(tuple((serial_number_parser, timestamp_parser)), n as usize)(rest)?;
            (rest, Group::FirstSeenReplyCouples(couple))
        }
        GroupCode::TransferableIndexedSigGroups(n) => {
            let (rest, quadruple) = count(transferable_quadruple, n as usize)(rest).unwrap();
            (rest, Group::TransferableIndexedSigGroups(quadruple))
        }
        GroupCode::LastEstSignaturesGroups(n) => {
            let (rest, couple) = count(identifier_signature_pair, n as usize)(rest)?;
            (rest, Group::LastEstSignaturesGroups(couple))
        }
        GroupCode::Frame(n) => {
            // n * 4 is all attachments length
            match nom::bytes::complete::take(n * 4)(rest) {
                Ok((rest, total)) => {
                    let (extra, atts) = many0(parse_group)(total)?;
                    if !extra.is_empty() {
                        // something is wrong, should not happend
                        return Err(nom::Err::Incomplete(Needed::Size(
                            NonZeroUsize::new((n * 4) as usize - rest.len()).unwrap(),
                        )));
                    } else {
                        (rest, Group::Frame(atts))
                    }
                }
                Err(nom::Err::Error((rest, _))) => {
                    return Err(nom::Err::Incomplete(Needed::Size(
                        NonZeroUsize::new((n * 4) as usize - rest.len()).unwrap(),
                    )))
                }
                Err(_e) => return Err(nom::Err::Error(make_error(stream, ErrorKind::IsNot))),
            }
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
    let group_str = "-EAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2022-10-25T12c04c30d175309p00c00";
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
    use crate::path::MaterialPath;

    let attached_str = "-LAZ5AABAA-a-AABAAFjjD99-xy7J0LGmCkSE_zYceED5uPF4q7l8J23nNQ64U-oWWulHI5dh3cFDWT4eICuEQCALdh8BO5ps-qx0qBA";
    let (_rest, attached_material) = parse_group(attached_str.as_bytes()).unwrap();
    let expected_path = MaterialPath::to_path("-a".into());
    if let Group::PathedMaterialQuadruplet(material_path, groups) = attached_material {
        assert_eq!(material_path, expected_path);
        assert_eq!(groups.len(), 1)
    };
}
