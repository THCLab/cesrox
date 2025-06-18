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
    AnchoringEventSeal, CesrPrimitive, Digest, IndexedSignature, PublicKey, Signature, Timestamp,
};

#[derive(Clone, Debug, PartialEq)]
pub enum Group {
    IndexedControllerSignatures(Vec<IndexedSignature>),
    IndexedWitnessSignatures(Vec<IndexedSignature>),
    NontransReceiptCouples(Vec<(PublicKey, Signature)>),
    SourceSealCouples(Vec<(u64, Digest)>),
    FirstSeenReplyCouples(Vec<(u64, Timestamp)>),
    AnchoringSeals(Vec<AnchoringEventSeal>),
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
            Group::AnchoringSeals(groups) => (
                GroupCode::AnchoringEventSeals(groups.len() as u16),
                groups
                    .iter()
                    .fold("".into(), |acc, (identifier, sn, digest)| {
                        [acc, identifier.to_str(), pack_sn(*sn), digest.to_str()].join("")
                    }),
            ),
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
