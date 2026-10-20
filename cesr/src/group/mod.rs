pub mod codes;
pub(crate) mod parsers;

pub use parsers::parse_group;

use crate::{
    derivation_code::DerivationCode,
    primitives::{
        codes::{rand_128::pack_sn, timestamp::pack_datetime, TagCode},
        Identifier, Nonce,
    },
    value::Value,
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
    pub nonce: Nonce,
    pub rel_id: Digest,
}

/// Receipt from a signer with a non-transferable identifier: its public key,
/// which is also its identifier, and its signature.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NontransReceiptCouple {
    pub key: PublicKey,
    pub signature: Signature,
}

/// Points at the event that anchors this one: its sequence number and
/// digest.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SealSourceCouple {
    pub sn: u64,
    pub digest: Digest,
}

/// When and in what order the sending node first saw an event.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FirstSeenReplayCouple {
    /// First-seen ordinal number.
    pub fnu: u64,
    pub timestamp: Timestamp,
}

/// Signatures by a transferable identifier, verified against the keys of
/// its latest establishment event.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TransLastIdxSigGroup {
    pub prefix: Identifier,
    pub signatures: Vec<IndexedSignature>,
}

#[derive(Debug, PartialEq, Clone)]
#[non_exhaustive]
pub enum Group {
    IndexedControllerSignatures(Vec<IndexedSignature>),
    IndexedWitnessSignatures(Vec<IndexedSignature>),
    NontransReceiptCouples(Vec<NontransReceiptCouple>),
    SourceSealCouples(Vec<SealSourceCouple>),
    FirstSeenReplayCouples(Vec<FirstSeenReplayCouple>),
    AnchoringSeals(Vec<AnchoringEventSeal>),
    /// CESR 2.0 `-Y` Trans Last Est Evt Indexed Signature Group(s).
    TransLastIdxSigGroups(Vec<TransLastIdxSigGroup>),
    #[cfg(feature = "cesr-proof")]
    PathedMaterialQuadruplet(MaterialPath, Vec<Group>),
    TSPPayload(Vec<Value>),
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
                couples.iter().fold("".into(), |acc, couple| {
                    [acc, couple.key.to_str(), couple.signature.to_str()].join("")
                }),
            ),
            Group::SourceSealCouples(quadruple) => (
                GroupCode::SealSourceCouples(quadruple.len() as u16),
                quadruple.iter().fold("".into(), |acc, couple| {
                    [acc, pack_sn(couple.sn), couple.digest.to_str()].join("")
                }),
            ),
            Group::FirstSeenReplayCouples(couples) => (
                GroupCode::FirstSeenReplayCouples(couples.len() as u16),
                couples.iter().fold("".into(), |acc, couple| {
                    [acc, pack_sn(couple.fnu), pack_datetime(&couple.timestamp)].join("")
                }),
            ),
            Group::AnchoringSeals(groups) => (
                GroupCode::AnchoringEventSeals(groups.len() as u16),
                groups.iter().fold("".into(), |acc, seal| {
                    [
                        acc,
                        seal.prefix.to_str(),
                        pack_sn(seal.sn),
                        seal.digest.to_str(),
                    ]
                    .join("")
                }),
            ),
            Group::TransLastIdxSigGroups(groups) => (
                GroupCode::TransLastIdxSigGroups(groups.len() as u16),
                groups.iter().fold("".into(), |acc, group| {
                    let inner =
                        Group::IndexedControllerSignatures(group.signatures.clone()).to_cesr_str();
                    [acc, group.prefix.to_str(), inner].join("")
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
            Group::TSPPayload(tsp_payload) => {
                let data_str = tsp_payload
                    .iter()
                    .map(|value| value.to_string())
                    .collect::<Vec<_>>()
                    .concat();
                (GroupCode::TSPPayload((data_str.len() / 4) as u16), data_str)
            }
        };
        [code.to_str(), value].concat()
    }
}
