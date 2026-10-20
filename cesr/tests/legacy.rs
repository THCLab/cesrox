//! Reading and writing the attachment format of cesrox before 2.0: item
//! counts in -K, -L, -M, -O, -S, -T and -Y and the old layout of
//! current-only indexed signatures.
#![cfg(feature = "legacy-v2beta")]

use cesrox::{
    group::{
        FirstSeenReplayCouple, Group, NontransReceiptCouple, SealSourceCouple, TransLastIdxSigGroup,
    },
    parse, parse_with,
    primitives::{
        codes::{
            attached_signature_code::{AttachedSignatureCode, Index},
            basic::Basic,
            self_addressing::SelfAddressing,
            self_signing::SelfSigning,
        },
        AnchoringEventSeal, Digest, Identifier, IdentifierCode, IndexedSignature, PublicKey,
        Signature,
    },
    Counting, Value,
};

fn sig(code: SelfSigning, index: Index, fill: u8) -> IndexedSignature {
    let len = if code == SelfSigning::Ed448 { 114 } else { 64 };
    IndexedSignature::new(AttachedSignatureCode::new(code, index), vec![fill; len])
}

fn digest(fill: u8) -> Digest {
    Digest::new(SelfAddressing::Blake3_256, vec![fill; 32])
}

fn prefix(fill: u8) -> Identifier {
    Identifier::new(
        IdentifierCode::SelfAddressing(SelfAddressing::Blake3_256),
        vec![fill; 32],
    )
}

/// One group of every counted kind, with current-only signatures whose
/// layout differs between the formats.
fn groups() -> Vec<Group> {
    let ed = SelfSigning::Ed25519Sha512;
    vec![
        Group::IndexedControllerSignatures(vec![sig(ed, Index::BothSame(0), 1)]),
        Group::IndexedControllerSignatures(vec![
            sig(ed, Index::BothSame(3), 2),
            sig(SelfSigning::Ed448, Index::Dual(0, 2), 3),
        ]),
        Group::IndexedWitnessSignatures(vec![
            sig(SelfSigning::Ed448, Index::CurrentOnly(5), 4),
            sig(ed, Index::BigCurrentOnly(100), 5),
            sig(
                SelfSigning::ECDSAsecp256k1Sha256,
                Index::BigCurrentOnly(70),
                6,
            ),
            sig(SelfSigning::Ed448, Index::BigCurrentOnly(300), 7),
        ]),
        Group::NontransReceiptCouples(vec![NontransReceiptCouple {
            key: PublicKey::new(Basic::Ed25519Nontrans, vec![8; 32]),
            signature: Signature::new(ed, vec![9; 64]),
        }]),
        Group::SourceSealCouples(vec![
            SealSourceCouple {
                sn: 1,
                digest: digest(10),
            },
            SealSourceCouple {
                sn: 2,
                digest: digest(11),
            },
        ]),
        Group::FirstSeenReplayCouples(vec![FirstSeenReplayCouple {
            fnu: 0,
            timestamp: "2022-10-25T12:04:30.175309+00:00".parse().unwrap(),
        }]),
        Group::AnchoringSeals(vec![AnchoringEventSeal {
            prefix: prefix(12),
            sn: 0,
            digest: digest(13),
        }]),
        Group::TransLastIdxSigGroups(vec![TransLastIdxSigGroup {
            prefix: prefix(14),
            signatures: vec![
                sig(ed, Index::BothSame(0), 15),
                sig(ed, Index::BothSame(1), 16),
            ],
        }]),
    ]
}

#[test]
fn both_formats_decode_to_the_same_groups() {
    for group in groups() {
        let v2 = group.to_cesr_str();
        let legacy = group.to_legacy_cesr_str();
        assert_ne!(v2, legacy, "formats should differ for {group:?}");

        let expected = vec![Value::SpecificGroup(group.clone())];
        assert_eq!(
            parse_with(v2.as_bytes(), Counting::Quadlets).unwrap(),
            expected
        );
        assert_eq!(
            parse_with(legacy.as_bytes(), Counting::LegacyItems).unwrap(),
            expected
        );
        // the default mode reads both
        assert_eq!(parse(v2.as_bytes()).unwrap(), expected, "{v2}");
        assert_eq!(parse(legacy.as_bytes()).unwrap(), expected, "{legacy}");
        // strict V2 rejects the old format
        assert!(
            parse_with(legacy.as_bytes(), Counting::Quadlets).is_err(),
            "{legacy}"
        );
    }
}

#[test]
fn old_counts_and_layouts_on_the_wire() {
    let ed448_current =
        Group::IndexedControllerSignatures(vec![sig(SelfSigning::Ed448, Index::CurrentOnly(5), 0)]);
    // one 156-character Ed448 signature: 1 item, or 39 quadlets
    assert!(ed448_current.to_legacy_cesr_str().starts_with("-KAB0BAF"));
    assert!(ed448_current.to_cesr_str().starts_with("-KAn0BFA"));

    let big_current = Group::IndexedControllerSignatures(vec![sig(
        SelfSigning::ECDSAsecp256k1Sha256,
        Index::BigCurrentOnly(100),
        0,
    )]);
    assert!(big_current.to_legacy_cesr_str().starts_with("-KAB2DAABk"));
    assert!(big_current.to_cesr_str().starts_with("-KAX2DBkAA"));
}

#[test]
fn v2_markers_switch_off_the_old_format() {
    let group = Group::IndexedControllerSignatures(vec![sig(
        SelfSigning::Ed25519Sha512,
        Index::BothSame(0),
        1,
    )]);
    let legacy = group.to_legacy_cesr_str();

    // after a V2 genus code the stream is V2
    let after_genus = format!("-_AAACAA{legacy}");
    assert!(parse(after_genus.as_bytes()).is_err());

    // so is the content of an attachment group
    let quadlets = cesrox::conversion::num_to_b64((legacy.len() / 4) as u16);
    let in_attachment_group = format!("-C{quadlets:A>2}{legacy}");
    assert!(parse(in_attachment_group.as_bytes()).is_err());
}

/// The default mode reads a group as V2 when its content splits exactly
/// into whole items. An old group of exactly 22 Ed25519 signatures also
/// does: its count, 22, is the size in quadlets of one signature. Such
/// data has to be read with `Counting::LegacyItems`.
#[test]
fn ambiguous_old_group_needs_explicit_mode() {
    let signatures: Vec<_> = (0..22)
        .map(|i| sig(SelfSigning::Ed25519Sha512, Index::BothSame(i), i as u8))
        .collect();
    let legacy = Group::IndexedControllerSignatures(signatures.clone()).to_legacy_cesr_str();
    assert!(legacy.starts_with("-KAW"));

    let explicit = parse_with(legacy.as_bytes(), Counting::LegacyItems).unwrap();
    assert_eq!(
        explicit,
        vec![Value::SpecificGroup(Group::IndexedControllerSignatures(
            signatures
        ))]
    );
    let guessed = parse(legacy.as_bytes());
    assert_ne!(guessed.ok(), Some(explicit));
}
