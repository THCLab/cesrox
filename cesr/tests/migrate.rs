//! Migrating CESR stored in the format of cesrox before 2.0.
#![cfg(feature = "legacy-v2beta")]

use cesrox::{
    migrate::{migrate, Options},
    parse_with,
    payload::Payload,
    universal_codes::{UniversalCode, UniversalGroupCode},
    Counting, Value,
};

/// A KEL written by keriox with cesrox before 2.0: two events with
/// controller signatures and witness receipts.
const LEGACY_KEL: &[u8] = include_bytes!("data/legacy_kel.cesr");

fn bodies(values: &[Value]) -> Vec<&Payload> {
    values
        .iter()
        .filter_map(|v| match v {
            Value::Payload(p) => Some(p),
            _ => None,
        })
        .collect()
}

#[test]
fn legacy_kel_becomes_v2_with_bodies_untouched() {
    let migration = migrate(LEGACY_KEL, &Options::default()).unwrap();
    assert!(migration.changed);

    let before = parse_with(LEGACY_KEL, Counting::LegacyItems).unwrap();
    let after = parse_with(&migration.output, Counting::Quadlets).unwrap();
    // the bodies, which signatures cover, are the same bytes
    assert_eq!(bodies(&before), bodies(&after));
    // each body is followed by one attachment group
    assert_eq!(after.len(), 4);
    assert!(matches!(
        &after[1],
        Value::UniversalGroup(UniversalGroupCode::Group { code: UniversalCode::Attachments, .. }, groups)
            if groups.len() == 3
    ));
    // strict V2 cannot read the old stream
    assert!(parse_with(LEGACY_KEL, Counting::Quadlets).is_err());
}

#[test]
fn migrating_twice_changes_nothing() {
    let once = migrate(LEGACY_KEL, &Options::default()).unwrap();
    let twice = migrate(&once.output, &Options::default()).unwrap();
    assert!(!twice.changed);
    assert_eq!(twice.output, once.output);
}

#[test]
fn bare_groups_when_not_wrapping() {
    let options = Options {
        wrap_attachments: false,
        ..Options::default()
    };
    let migration = migrate(LEGACY_KEL, &options).unwrap();
    let after = parse_with(&migration.output, Counting::Quadlets).unwrap();
    assert_eq!(after.len(), 8);
    assert!(after
        .iter()
        .all(|v| matches!(v, Value::Payload(_) | Value::SpecificGroup(_))));
}

#[test]
fn v2_input_is_returned_unchanged() {
    let v2 = migrate(LEGACY_KEL, &Options::default()).unwrap().output;
    let unwrapped = migrate(
        LEGACY_KEL,
        &Options {
            wrap_attachments: false,
            ..Options::default()
        },
    )
    .unwrap()
    .output;
    for input in [v2, unwrapped] {
        let migration = migrate(&input, &Options::default()).unwrap();
        assert!(!migration.changed);
        assert_eq!(migration.output, input);
    }
}

#[test]
fn invalid_input_is_an_error() {
    assert!(migrate(b"-KABnot-cesr", &Options::default()).is_err());
    assert!(migrate(&LEGACY_KEL[..LEGACY_KEL.len() - 5], &Options::default()).is_err());
}
