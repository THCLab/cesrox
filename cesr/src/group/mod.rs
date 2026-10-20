pub mod codes;
pub(crate) mod parsers;

pub use parsers::{parse_group, parse_group_with};

use crate::{
    derivation_code::DerivationCode,
    primitives::{
        codes::{number::pack_number, rand_128::pack_sn, timestamp::pack_datetime, TagCode},
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
    pub sn: u128,
    pub digest: Digest,
}

/// When and in what order the sending node first saw an event.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FirstSeenReplayCouple {
    /// First-seen ordinal number.
    pub fnu: u128,
    pub timestamp: Timestamp,
}

/// Signatures by a transferable identifier, verified against the keys of
/// its latest establishment event.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TransLastIdxSigGroup {
    pub prefix: Identifier,
    pub signatures: Vec<IndexedSignature>,
}

/// `-V`: a backer's identifier and the digest of its registrar event.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BackerSeal {
    pub prefix: Identifier,
    pub digest: Digest,
}

/// `-W`: a digest tagged with the protocol and version it refers to.
#[derive(Debug, PartialEq, Clone)]
pub struct TypedDigestSeal {
    /// Protocol and version tag, e.g. `YKERICAA`.
    pub kind: Value,
    /// Digest, salt or empty value.
    pub digest: Value,
}

/// `-X`: signatures by a transferable identifier, verified against the
/// keys of the event with the given sequence number and digest.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TransIdxSigGroup {
    pub prefix: Identifier,
    pub sn: u128,
    pub digest: Digest,
    pub signatures: Vec<IndexedSignature>,
}

/// `-a`: a blinded state of a registry: blinding digest, salty nonce
/// (UUID), transaction event SAID and state label.
#[derive(Debug, PartialEq, Clone)]
pub struct BlindedState {
    pub digest: Value,
    pub uuid: Value,
    pub said: Value,
    pub state: Value,
}

/// `-b`: a blinded state bound to a key event by its sequence number and
/// SAID.
#[derive(Debug, PartialEq, Clone)]
pub struct BoundState {
    pub digest: Value,
    pub uuid: Value,
    pub said: Value,
    pub state: Value,
    pub bound_sn: u128,
    pub bound_said: Value,
}

/// `-c`: a blinded IANA media type and value.
#[derive(Debug, PartialEq, Clone)]
pub struct TypedMedia {
    pub digest: Value,
    pub uuid: Value,
    pub media_type: Value,
    pub media: Value,
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
    /// `-Q`
    DigestSeals(Vec<Digest>),
    /// `-R`
    MerkleRootSeals(Vec<Digest>),
    /// `-U`: identifiers whose latest establishment event is the source.
    /// The spec text says `aid+dig` but calls them singles; they are written
    /// as the identifier only, as in the shared test vectors.
    LastEventSeals(Vec<Identifier>),
    /// `-V`
    BackerSeals(Vec<BackerSeal>),
    /// `-W`
    TypedDigestSeals(Vec<TypedDigestSeal>),
    /// `-X`
    TransIdxSigGroups(Vec<TransIdxSigGroup>),
    /// `-a`
    BlindedStates(Vec<BlindedState>),
    /// `-b`
    BoundStates(Vec<BoundState>),
    /// `-c`
    TypedMedia(Vec<TypedMedia>),
    #[cfg(feature = "cesr-proof")]
    PathedMaterialQuadruplet(MaterialPath, Vec<Group>),
    TSPPayload(Vec<Value>),
}

impl Group {
    /// Encodes the group in the CESR V2 text domain.
    pub fn to_cesr_str(&self) -> String {
        self.encode(false)
    }

    /// Encodes the group as cesrox did before 2.0, with item counts and the
    /// old layout of current-only indexed signatures, for peers that have
    /// not been upgraded yet.
    #[cfg(feature = "legacy-v2beta")]
    pub fn to_legacy_cesr_str(&self) -> String {
        self.encode(true)
    }

    fn encode(&self, legacy: bool) -> String {
        let signatures = |sigs: &[IndexedSignature]| {
            sigs.iter()
                .map(|sig| indexed_signature_text(sig, legacy))
                .collect::<String>()
        };
        // V2 writes sequence numbers as Number primitives, the old format
        // as 128-bit salts
        let number = |n: u128| if legacy { pack_sn(n) } else { pack_number(n) };
        // V2 counts the quadlets of the body, the old format its items
        let counted = |code: fn(u32) -> GroupCode, items: usize, body: String| {
            let count = if legacy { items } else { body.len() / 4 };
            [code(count as u32).to_str(), body].concat()
        };
        // groups that only exist in V2
        let quadlets = |code: fn(u32) -> GroupCode, body: String| {
            [code((body.len() / 4) as u32).to_str(), body].concat()
        };
        match self {
            Group::IndexedControllerSignatures(sigs) => counted(
                GroupCode::IndexedControllerSignatures,
                sigs.len(),
                signatures(sigs),
            ),
            Group::IndexedWitnessSignatures(sigs) => counted(
                GroupCode::IndexedWitnessSignatures,
                sigs.len(),
                signatures(sigs),
            ),
            Group::NontransReceiptCouples(couples) => counted(
                GroupCode::NontransferableReceiptCouples,
                couples.len(),
                couples
                    .iter()
                    .map(|couple| couple.key.to_str() + &couple.signature.to_str())
                    .collect(),
            ),
            Group::SourceSealCouples(couples) => counted(
                GroupCode::SealSourceCouples,
                couples.len(),
                couples
                    .iter()
                    .map(|couple| number(couple.sn) + &couple.digest.to_str())
                    .collect(),
            ),
            Group::FirstSeenReplayCouples(couples) => counted(
                GroupCode::FirstSeenReplayCouples,
                couples.len(),
                couples
                    .iter()
                    .map(|couple| number(couple.fnu) + &pack_datetime(&couple.timestamp))
                    .collect(),
            ),
            Group::AnchoringSeals(seals) => counted(
                GroupCode::AnchoringEventSeals,
                seals.len(),
                seals
                    .iter()
                    .map(|seal| {
                        [seal.prefix.to_str(), number(seal.sn), seal.digest.to_str()].concat()
                    })
                    .collect(),
            ),
            Group::TransLastIdxSigGroups(groups) => counted(
                GroupCode::TransLastIdxSigGroups,
                groups.len(),
                groups
                    .iter()
                    .map(|group| {
                        let inner = Group::IndexedControllerSignatures(group.signatures.clone());
                        group.prefix.to_str() + &inner.encode(legacy)
                    })
                    .collect(),
            ),
            Group::DigestSeals(digests) => quadlets(
                GroupCode::DigestSeals,
                digests.iter().map(|d| d.to_str()).collect(),
            ),
            Group::MerkleRootSeals(roots) => quadlets(
                GroupCode::MerkleRootSeals,
                roots.iter().map(|d| d.to_str()).collect(),
            ),
            Group::LastEventSeals(prefixes) => quadlets(
                GroupCode::LastEventSeals,
                prefixes.iter().map(|p| p.to_str()).collect(),
            ),
            Group::BackerSeals(seals) => quadlets(
                GroupCode::BackerSeals,
                seals
                    .iter()
                    .map(|seal| seal.prefix.to_str() + &seal.digest.to_str())
                    .collect(),
            ),
            Group::TypedDigestSeals(seals) => quadlets(
                GroupCode::TypedDigestSeals,
                seals
                    .iter()
                    .map(|seal| seal.kind.to_string() + &seal.digest.to_string())
                    .collect(),
            ),
            Group::TransIdxSigGroups(groups) => quadlets(
                GroupCode::TransIdxSigGroups,
                groups
                    .iter()
                    .map(|group| {
                        let signatures =
                            Group::IndexedControllerSignatures(group.signatures.clone());
                        [
                            group.prefix.to_str(),
                            pack_number(group.sn),
                            group.digest.to_str(),
                            signatures.encode(false),
                        ]
                        .concat()
                    })
                    .collect(),
            ),
            Group::BlindedStates(states) => quadlets(
                GroupCode::BlindedStates,
                states
                    .iter()
                    .map(|s| {
                        [&s.digest, &s.uuid, &s.said, &s.state]
                            .map(Value::to_string)
                            .concat()
                    })
                    .collect(),
            ),
            Group::BoundStates(states) => quadlets(
                GroupCode::BoundStates,
                states
                    .iter()
                    .map(|s| {
                        [&s.digest, &s.uuid, &s.said, &s.state]
                            .map(Value::to_string)
                            .concat()
                            + &pack_number(s.bound_sn)
                            + &s.bound_said.to_string()
                    })
                    .collect(),
            ),
            Group::TypedMedia(media) => quadlets(
                GroupCode::TypedMedia,
                media
                    .iter()
                    .map(|m| {
                        [&m.digest, &m.uuid, &m.media_type, &m.media]
                            .map(Value::to_string)
                            .concat()
                    })
                    .collect(),
            ),
            #[cfg(feature = "cesr-proof")]
            Group::PathedMaterialQuadruplet(path, attachments) => {
                let attachments: String = attachments.iter().map(|g| g.encode(legacy)).collect();
                let attached_text = path.to_cesr() + &attachments;
                let code = GroupCode::PathedMaterialQuadruple((attached_text.len() / 4) as u32);
                [code.to_str(), attached_text].concat()
            }
            Group::TSPPayload(tsp_payload) => {
                let data_str: String = tsp_payload.iter().map(|value| value.to_string()).collect();
                let code = GroupCode::TSPPayload((data_str.len() / 4) as u32);
                [code.to_str(), data_str].concat()
            }
        }
    }
}

fn indexed_signature_text(sig: &IndexedSignature, legacy: bool) -> String {
    #[cfg(feature = "legacy-v2beta")]
    if legacy {
        let code = sig.code.to_legacy_str();
        // the code replaces the lead bytes of the raw text
        let lead = code.len() % 4;
        let text = crate::conversion::from_bytes_to_text(&sig.raw);
        return code + text.get(lead..).unwrap_or_default();
    }
    let _ = legacy;
    sig.to_str()
}
