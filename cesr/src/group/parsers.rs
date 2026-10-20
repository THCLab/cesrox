use std::str::FromStr;

use nom::{bytes::complete::take, multi::many0, Parser};

use crate::{
    error::Error,
    parsing::{ascii, code_error, error, failure, finish, framed, Ctx, Failure, PResult},
    primitives::{
        codes::{
            attached_signature_code::AttachedSignatureCode, basic::Basic,
            self_addressing::SelfAddressing, self_signing::SelfSigning,
        },
        parsers::{
            anchoring_event_seal, identifier, primitive, primitive_with, serial_number, timestamp,
        },
        IndexedSignature,
    },
    value::{parse_value_at, MAX_NESTING},
    Counting, Parsed,
};

use super::{
    codes::GroupCode, FirstSeenReplayCouple, Group, NontransReceiptCouple, SealSourceCouple,
    TransLastIdxSigGroup,
};

/// Parses one attachment group at the start of `input`. Returns the group
/// and the rest of the input.
pub fn parse_group(input: &[u8]) -> Parsed<'_, Group> {
    parse_group_with(input, Counting::default())
}

/// [`parse_group`] with an explicit way of reading group counts.
pub fn parse_group_with(input: &[u8], counting: Counting) -> Parsed<'_, Group> {
    finish(input, parse_group_at(input, Ctx::new(counting)))
}

/// How the count of a group is read.
#[derive(Clone, Copy)]
enum Framing {
    /// CESR V2: the group occupies `count` quadlets.
    Quadlets,
    /// cesrox before 2.0: the group holds `count` items.
    #[cfg(feature = "legacy-v2beta")]
    Items,
}

/// Reads the `n` counted entries of a group with `item`.
fn entries<'a, T>(
    input: &'a [u8],
    n: u16,
    framing: Framing,
    mut item: impl Parser<&'a [u8], Output = T, Error = Failure<'a>>,
) -> PResult<'a, Vec<T>> {
    match framing {
        #[cfg(feature = "legacy-v2beta")]
        Framing::Items => nom::multi::count(item, n as usize).parse(input),
        Framing::Quadlets => {
            let (rest, mut content) = take(n as usize * 4)(input)?;
            let mut out = vec![];
            while !content.is_empty() {
                let (more, entry) = framed(item.parse(content))?;
                out.push(entry);
                content = more;
            }
            Ok((rest, out))
        }
    }
}

fn indexed_signature(input: &[u8], framing: Framing) -> PResult<'_, IndexedSignature> {
    let legacy = match framing {
        Framing::Quadlets => false,
        #[cfg(feature = "legacy-v2beta")]
        Framing::Items => true,
    };
    primitive_with(input, |s| AttachedSignatureCode::parse(s, legacy))
}

/// Parse a single entry inside a `TransLastIdxSigGroups` (`-Y`) group: the
/// identifier prefix followed by an inner `IndexedControllerSignatures`
/// (`-K`) group whose payload becomes the indexed signatures.
fn trans_last_entry(input: &[u8], ctx: Ctx) -> PResult<'_, TransLastIdxSigGroup> {
    let (rest, prefix) = identifier(input)?;
    let (rest, inner) = parse_group_at(rest, ctx.nested())?;
    match inner {
        Group::IndexedControllerSignatures(signatures) => {
            Ok((rest, TransLastIdxSigGroup { prefix, signatures }))
        }
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

/// Reads the entries of one of the counted attachment groups.
fn counted_group<'a>(
    rest: &'a [u8],
    code: &GroupCode,
    framing: Framing,
    ctx: Ctx,
) -> PResult<'a, Group> {
    // nested groups follow the framing chosen for this one
    let ctx = ctx.with_counting(match framing {
        Framing::Quadlets => Counting::Quadlets,
        #[cfg(feature = "legacy-v2beta")]
        Framing::Items => Counting::LegacyItems,
    });
    let signatures = |s| indexed_signature(s, framing);
    match *code {
        GroupCode::IndexedControllerSignatures(n) => entries(rest, n, framing, signatures)
            .map(|(rest, sigs)| (rest, Group::IndexedControllerSignatures(sigs))),
        GroupCode::IndexedWitnessSignatures(n) => entries(rest, n, framing, signatures)
            .map(|(rest, sigs)| (rest, Group::IndexedWitnessSignatures(sigs))),
        GroupCode::NontransferableReceiptCouples(n) => {
            let couple = (primitive::<Basic>, primitive::<SelfSigning>)
                .map(|(key, signature)| NontransReceiptCouple { key, signature });
            entries(rest, n, framing, couple)
                .map(|(rest, couples)| (rest, Group::NontransReceiptCouples(couples)))
        }
        GroupCode::SealSourceCouples(n) => {
            let couple = (serial_number, primitive::<SelfAddressing>)
                .map(|(sn, digest)| SealSourceCouple { sn, digest });
            entries(rest, n, framing, couple)
                .map(|(rest, couples)| (rest, Group::SourceSealCouples(couples)))
        }
        GroupCode::FirstSeenReplayCouples(n) => {
            let couple = (serial_number, timestamp)
                .map(|(fnu, timestamp)| FirstSeenReplayCouple { fnu, timestamp });
            entries(rest, n, framing, couple)
                .map(|(rest, couples)| (rest, Group::FirstSeenReplayCouples(couples)))
        }
        GroupCode::AnchoringEventSeals(n) => entries(rest, n, framing, anchoring_event_seal)
            .map(|(rest, seals)| (rest, Group::AnchoringSeals(seals))),
        GroupCode::TransLastIdxSigGroups(n) => {
            entries(rest, n, framing, |s| trans_last_entry(s, ctx))
                .map(|(rest, groups)| (rest, Group::TransLastIdxSigGroups(groups)))
        }
        _ => error(rest, Error::UnknownCode),
    }
}

fn is_counted(code: &GroupCode) -> bool {
    matches!(
        code,
        GroupCode::IndexedControllerSignatures(_)
            | GroupCode::IndexedWitnessSignatures(_)
            | GroupCode::NontransferableReceiptCouples(_)
            | GroupCode::SealSourceCouples(_)
            | GroupCode::FirstSeenReplayCouples(_)
            | GroupCode::AnchoringEventSeals(_)
            | GroupCode::TransLastIdxSigGroups(_)
    )
}

/// Parses one group at the position described by `ctx`; see
/// [`MAX_NESTING`].
pub(crate) fn parse_group_at(stream: &[u8], ctx: Ctx) -> PResult<'_, Group> {
    if ctx.depth > MAX_NESTING {
        return failure(stream, Error::NestingTooDeep);
    }
    let (rest, group_code) = group_code(stream)?;
    if is_counted(&group_code) {
        return match ctx.counting {
            Counting::Quadlets => counted_group(rest, &group_code, Framing::Quadlets, ctx),
            #[cfg(feature = "legacy-v2beta")]
            Counting::LegacyItems => counted_group(rest, &group_code, Framing::Items, ctx),
            #[cfg(feature = "legacy-v2beta")]
            Counting::Auto => match counted_group(rest, &group_code, Framing::Quadlets, ctx) {
                Ok(parsed) => Ok(parsed),
                Err(nom::Err::Failure(f)) => Err(nom::Err::Failure(f)),
                Err(quadlets) => {
                    match counted_group(rest, &group_code, Framing::Items, ctx) {
                        Ok(parsed) => Ok(parsed),
                        // a stream reader must learn that more data is needed
                        Err(items) if is_incomplete(&items) => Err(items),
                        Err(_) => Err(quadlets),
                    }
                }
            },
        };
    }
    Ok(match group_code {
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
                            match MaterialPath::new(lb.clone(), value) {
                                Ok(path) => path,
                                Err(e) => return error(total, e),
                            }
                        }
                        _ => {
                            return error(total, Error::Invalid("expected a material path".into()))
                        }
                    };
                    let (_extra, attachment) =
                        many0(|s| parse_group_at(s, ctx.nested())).parse(extra)?;

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
                let (rest, values) = many0(|s| parse_value_at(s, ctx.nested())).parse(total)?;
                if !rest.is_empty() {
                    return error(total, Error::Invalid("unparsed data in TSP payload".into()));
                }
                Ok((main_rest, Group::TSPPayload(values)))
            }
            Err(e) => Err(e),
        }?,
        // counted groups are handled above
        _ => return error(stream, Error::UnknownCode),
    })
}

#[cfg(feature = "legacy-v2beta")]
fn is_incomplete(error: &nom::Err<Failure<'_>>) -> bool {
    matches!(
        error,
        nom::Err::Error(f) if matches!(f.error, Error::Incomplete { .. })
    )
}

#[cfg(test)]
mod tests {
    use super::parse_group;
    use crate::{
        group::{FirstSeenReplayCouple, Group, TransLastIdxSigGroup},
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

        let (_, prefix) = identifier(id_str.as_bytes()).unwrap();
        let (signature, _) = parse_primitive::<AttachedSignatureCode>(sig_str.as_bytes()).unwrap();

        let group = Group::TransLastIdxSigGroups(vec![TransLastIdxSigGroup {
            prefix,
            signatures: vec![signature],
        }]);
        let encoded = group.to_cesr_str();
        // 44 prefix + 4 counter + 88 signature characters = 34 quadlets
        assert!(encoded.starts_with("-YAi"), "encoded = {encoded}");

        let (parsed, rest) = parse_group(encoded.as_bytes()).unwrap();
        assert!(rest.is_empty(), "leftover bytes: {rest:?}");
        assert_eq!(parsed, group);
    }

    #[test]
    fn test_parse_group() {
        use crate::primitives::Timestamp;
        let group_str = "-OAKMAAA1AAG2022-10-25T12c04c30d175309p00c00";
        let (group, _rest) = parse_group(group_str.as_bytes()).unwrap();
        let expected = FirstSeenReplayCouple {
            fnu: 0,
            timestamp: "2022-10-25T12:04:30.175309+00:00"
                .parse::<Timestamp>()
                .unwrap(),
        };
        assert_eq!(group, Group::FirstSeenReplayCouples(vec![expected]));
    }

    #[cfg(feature = "cesr-proof")]
    #[test]
    fn test_pathed_material() {
        use crate::cesr_proof::MaterialPath;

        let attached_str = "-PAZ5AABAA-a-KAWAABjjD99-xy7J0LGmCkSE_zYceED5uPF4q7l8J23nNQ64U-oWWulHI5dh3cFDWT4eICuEQCALdh8BO5ps-qx0qBA";
        let (attached_material, _rest) = parse_group(attached_str.as_bytes()).unwrap();
        let expected_path = MaterialPath::create_from_str("-a".into()).unwrap();
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
        let (tag, _) = parse_primitive::<TagCode>(msg_type.as_bytes()).unwrap();
        let tag = tag.code;

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
