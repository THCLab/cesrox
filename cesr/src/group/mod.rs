pub mod codes;
pub mod parsers;

use crate::{
    derivation_code::DerivationCode,
    primitives::{codes::{serial_number::pack_sn, timestamp::pack_datetime, PrimitiveCode, TagCode}, Identifier, SaltyNounce},
};

use self::codes::GroupCode;

#[cfg(feature = "cesr-proof")]
use super::cesr_proof::MaterialPath;
use super::primitives::{
    AnchoringEventSeal, CesrPrimitive, Digest, IndexedSignature, PublicKey, Signature, Timestamp,
};


#[derive(Debug, PartialEq)]
pub struct TSPPayload {
    pub tag: TagCode, 
    pub source_id: Identifier, 
    pub said: Digest, 
    pub nonce: SaltyNounce, 
    pub rel_id: Digest
}

#[derive(Debug, PartialEq)]
pub enum Group {
    IndexedControllerSignatures(Vec<IndexedSignature>),
    IndexedWitnessSignatures(Vec<IndexedSignature>),
    NontransReceiptCouples(Vec<(PublicKey, Signature)>),
    SourceSealCouples(Vec<(u64, Digest)>),
    FirstSeenReplyCouples(Vec<(u64, Timestamp)>),
    AnchoringSeals(Vec<AnchoringEventSeal>),
    #[cfg(feature = "cesr-proof")]
    PathedMaterialQuadruplet(MaterialPath, Vec<Group>),
    TSPPayload(Vec<TSPPayload>),
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
            Group::TSPPayload(data) => {
                let data_str = data
                    .iter()
                    .map(|tsp_payload| {
                        format!(
                            "{}{}{}{}{}",
                            tsp_payload.tag.to_str(),
                            tsp_payload.source_id.to_str(),
                            tsp_payload.said.to_str(),
                            tsp_payload.nonce.to_str(),
                            tsp_payload.rel_id.to_str()
                        )
                    })
                    .fold(String::new(), |a, b| a + &b);
                (GroupCode::TSPPayload((data_str.len()/4) as u16), data_str)
            }
        };
        [code.to_str(), value].concat()
    }
}
