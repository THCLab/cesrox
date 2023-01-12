pub mod codes;
pub mod parsers;

use crate::{
    derivation_code::DerivationCode,
    primitives::codes::{serial_number::pack_sn, timestamp::pack_datetime},
};

use self::codes::GroupCode;

#[cfg(feature = "cesr-proof")]
use super::cesr_proof::MaterialPath;
use super::primitives::{
    CesrPrimitive, Digest, IdentifierSignaturesCouple, IndexedSignature, PublicKey, Signature,
    Timestamp, TransferableQuadruple,
};

#[derive(Clone, Debug, PartialEq)]
pub enum Group {
    IndexedControllerSignatures(Vec<IndexedSignature>),
    IndexedWitnessSignatures(Vec<IndexedSignature>),
    NontransReceiptCouples(Vec<(PublicKey, Signature)>),
    SourceSealCouples(Vec<(u64, Digest)>),
    FirstSeenReplyCouples(Vec<(u64, Timestamp)>),
    TransIndexedSigGroups(Vec<TransferableQuadruple>),
    LastEstSignaturesGroups(Vec<IdentifierSignaturesCouple>),
    Frame(Vec<Group>),

    #[cfg(feature = "cesr-proof")]
    PathedMaterialQuadruplet(MaterialPath, Vec<Group>),
}

impl Group {
    pub fn to_cesr_str(&self) -> String {
        let (code, value) = match self {
            Group::IndexedControllerSignatures(sigs) => (
                GroupCode::IndexedControllerSignatures(sigs.len() as u16),
                sigs.iter()
                    .fold("".into(), |acc, s| [acc, s.to_str()].join("")),
            ),
            Group::IndexedWitnessSignatures(sigs) => (
                GroupCode::IndexedWitnessSignatures(sigs.len() as u16),
                sigs.iter()
                    .fold("".into(), |acc, s| [acc, s.to_str()].join("")),
            ),
            Group::NontransReceiptCouples(couples) => (
                GroupCode::NontransferableReceiptCouples(couples.len() as u16),
                couples
                    .iter()
                    .fold("".into(), |acc, (identifeir, signature)| {
                        [acc, identifeir.to_str(), signature.to_str()].join("")
                    }),
            ),
            Group::SourceSealCouples(quadruple) => (
                GroupCode::SealSourceCouples(quadruple.len() as u16),
                quadruple.iter().fold("".into(), |acc, (sn, digest)| {
                    [acc, pack_sn(*sn), digest.to_str()].join("")
                }),
            ),
            Group::FirstSeenReplyCouples(couples) => (
                GroupCode::FirstSeenReplyCouples(couples.len() as u16),
                couples.iter().fold("".into(), |acc, (sn, dt)| {
                    [acc, pack_sn(*sn), pack_datetime(dt)].join("")
                }),
            ),
            Group::TransIndexedSigGroups(groups) => (
                GroupCode::TransferableIndexedSigGroups(groups.len() as u16),
                groups
                    .iter()
                    .fold("".into(), |acc, (identifier, sn, digest, signatures)| {
                        let signatures_str = signatures
                            .iter()
                            .fold("".into(), |acc, s| [acc, s.to_str()].join(""));
                        [
                            acc,
                            identifier.to_str(),
                            pack_sn(*sn),
                            digest.to_str(),
                            GroupCode::IndexedControllerSignatures(signatures.len() as u16)
                                .to_str(),
                            signatures_str,
                        ]
                        .join("")
                    }),
            ),
            Group::LastEstSignaturesGroups(couples) => (
                GroupCode::LastEstSignaturesGroups(couples.len() as u16),
                couples
                    .iter()
                    .fold("".into(), |acc, (identifier, signatures)| {
                        let sigs = Group::IndexedControllerSignatures(signatures.to_vec());
                        [acc, identifier.to_str(), sigs.to_cesr_str()].join("")
                    }),
            ),
            Group::Frame(att) => {
                let data = att
                    .iter()
                    .fold("".to_string(), |acc, att| [acc, att.to_cesr_str()].concat());
                let code = GroupCode::Frame(data.len() as u16);
                (code, data)
            }

            #[cfg(feature = "cesr-proof")]
            Group::PathedMaterialQuadruplet(path, attachments) => {
                let attachments = attachments
                    .iter()
                    .map(|s| s.to_cesr_str())
                    .fold(String::new(), |a, b| a + &b);
                let attached_text = path.to_cesr() + &attachments;
                (
                    GroupCode::PathedMaterialQuadruple((attached_text.len() / 4) as u16),
                    attached_text,
                )
            }
        };
        [code.to_str(), value].concat()
    }
}
