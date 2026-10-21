//! Checks cesrox against the CESR V2 vectors of every source in
//! `test-vectors/v2`. Known gaps are listed in `vectors_expected_failures.txt`.

#[path = "../../test-vectors/harness.rs"]
mod harness;

use std::str::FromStr;

use cesrox::{
    conversion::qb64_to_qb2,
    derivation_code::DerivationCode,
    group::{codes::GroupCode, parse_group_with, Group},
    parse, parse_value,
    primitives::{codes::attached_signature_code::AttachedSignatureCode, parse_primitive},
    universal_codes::UniversalGroupCode,
    value::Value,
    Counting,
};
use harness::{field, Runner};

const EXPECTED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors_expected_failures.txt"
);

#[test]
fn v2_vectors() {
    let Some(mut r) = Runner::new(env!("CARGO_MANIFEST_DIR")) else {
        return;
    };
    for source in r.sources() {
        r.use_source(&source);
        primitives(&mut r);
        indexed(&mut r);
        counters(&mut r);
        groups(&mut r);
        streams(&mut r);
        #[cfg(feature = "legacy-v2beta")]
        migrations(&mut r);
        negative(&mut r);
    }
    r.finish(EXPECTED, false);
}

/// parse_value must consume the primitive, report the vector's code and raw bytes,
/// and re-encode to the same text.
fn primitives(r: &mut Runner) {
    for file in [
        "primitives/fixed.json",
        "primitives/variable.json",
        "primitives/special.json",
    ] {
        for v in r.load(file) {
            let (qb64, code, raw) = (field(&v, "qb64"), field(&v, "code"), field(&v, "raw_hex"));
            let qb2 = field(&v, "qb2_hex");
            r.check(&field(&v, "id"), move || {
                let (val, rest) =
                    parse_value(qb64.as_bytes()).map_err(|e| format!("parse error: {e}"))?;
                if !rest.is_empty() {
                    return Err(format!("unconsumed: {rest:?}"));
                }
                let encoded = val.to_string();
                if encoded != qb64 {
                    return Err(format!("re-encoded as {encoded}"));
                }
                let binary = val.to_qb2().map_err(|e| format!("binary: {e}"))?;
                if hex::encode(binary) != qb2 {
                    return Err("binary form differs".into());
                }
                match &val {
                    Value::Primitive(p) => {
                        if p.code.to_str() != code {
                            return Err(format!("code {} != {code}", p.code.to_str()));
                        }
                        if hex::encode(&p.raw) != raw {
                            return Err(format!("raw {} != {raw}", hex::encode(&p.raw)));
                        }
                    }
                    Value::VariableLengthRaw(p) => {
                        if hex::encode(p.value()) != raw {
                            return Err(format!("raw {} != {raw}", hex::encode(p.value())));
                        }
                    }
                    // tags carry no raw bytes; the text round trip above covers them
                    Value::Tag(_) => {}
                    other => return Err(format!("unexpected value {other:?}")),
                }
                Ok(())
            });
        }
    }
}

/// Indexed signatures: code, index, ondex and raw bytes as in the vector.
fn indexed(r: &mut Runner) {
    for v in r.load("indexed/indexers.json") {
        let (qb64, raw) = (field(&v, "qb64"), field(&v, "raw_hex"));
        let qb2 = field(&v, "qb2_hex");
        let index = v["index"].as_u64().unwrap_or_default();
        let ondex = v["ondex"].as_u64();
        r.check(&field(&v, "id"), move || {
            let (sig, rest) = parse_primitive::<AttachedSignatureCode>(qb64.as_bytes())
                .map_err(|e| format!("parse error: {e}"))?;
            let (c, bytes) = (sig.code, sig.raw);
            if !rest.is_empty() {
                return Err(format!("unconsumed {} chars", rest.len()));
            }
            if hex::encode(&bytes) != raw {
                return Err("raw mismatch".into());
            }
            if u64::from(c.index.current()) != index {
                return Err(format!("index {} != {index}", c.index.current()));
            }
            if c.index.prev_next().map(u64::from) != ondex {
                return Err(format!("ondex {:?} != {ondex:?}", c.index.prev_next()));
            }
            let encoded = format!("{}{}", c.to_str(), &qb64[c.code_size()..]);
            if encoded != qb64 {
                return Err(format!(
                    "re-encoded code {} != {}",
                    c.to_str(),
                    &qb64[..c.code_size()]
                ));
            }
            let binary = qb64_to_qb2(encoded.as_bytes()).map_err(|e| format!("binary: {e}"))?;
            if hex::encode(binary) != qb2 {
                return Err("binary form differs".into());
            }
            Ok(())
        });
    }
}

/// Counters: code and count must parse and re-encode to the same counter.
fn counters(r: &mut Runner) {
    for v in r.load("counters/counters.json") {
        let qb64 = field(&v, "qb64");
        let count = v["count"].as_u64().unwrap_or_default();
        r.check(&field(&v, "id"), move || {
            let b = qb64.as_bytes();
            if b.get(1) == Some(&b'_') {
                let (val, _) =
                    parse_value(qb64.as_bytes()).map_err(|e| format!("parse error: {e}"))?;
                let encoded = val.to_string();
                return if encoded == qb64 {
                    Ok(())
                } else {
                    Err(format!("re-encoded as {encoded}"))
                };
            }
            let universal = |c: Option<&u8>| matches!(c, Some(b'A'..=b'J'));
            if universal(b.get(1)) || (b.get(1) == Some(&b'-') && universal(b.get(2))) {
                let c = UniversalGroupCode::from_str(&qb64[1..])
                    .map_err(|e| format!("parse error: {e}"))?;
                return if c.value_size() as u64 == count {
                    Ok(())
                } else {
                    Err(format!("count {} != {count}", c.value_size()))
                };
            }
            let c = GroupCode::from_str(&qb64).map_err(|e| format!("unsupported: {e}"))?;
            if u64::from(c.count()) != count {
                return Err(format!("count {} != {count}", c.count()));
            }
            // a big code with a small count is written back in the small form
            let encoded = c.to_str();
            if GroupCode::from_str(&encoded) != Ok(c) {
                return Err(format!("re-encoded as {encoded}"));
            }
            Ok(())
        });
    }
}

/// Groups built from primitives: parsed as V2, every item read,
/// and written back to the same text.
fn groups(r: &mut Runner) {
    for v in r.load("groups/groups.json") {
        let qb64 = field(&v, "qb64");
        let qb2 = hex::decode(field(&v, "qb2_hex")).unwrap_or_default();
        let items = v["items"].as_u64().unwrap_or_default() as usize;
        r.check(&field(&v, "id"), move || {
            let (group, rest) = parse_group_with(qb64.as_bytes(), Counting::Quadlets)
                .map_err(|e| format!("parse error: {e}"))?;
            if !rest.is_empty() {
                return Err(format!("unconsumed {} chars", rest.len()));
            }
            let parsed = item_count(&group);
            if parsed != Some(items) {
                return Err(format!("{parsed:?} items, expected {items}"));
            }
            let encoded = group.to_cesr_str();
            if encoded != qb64 {
                return Err(format!("re-encoded as {encoded}"));
            }
            // the binary domain holds the same group
            let from_binary = parse(&qb2).map_err(|e| format!("binary parse error: {e}"))?;
            if from_binary != [Value::SpecificGroup(group.clone())] {
                return Err("binary form parses differently".into());
            }
            if group.to_qb2().map_err(|e| format!("binary: {e}"))? != qb2 {
                return Err("binary form differs".into());
            }
            Ok(())
        });
    }
}

fn item_count(group: &Group) -> Option<usize> {
    Some(match group {
        Group::IndexedControllerSignatures(v) | Group::IndexedWitnessSignatures(v) => v.len(),
        Group::NontransReceiptCouples(v) => v.len(),
        Group::SourceSealCouples(v) => v.len(),
        Group::FirstSeenReplayCouples(v) => v.len(),
        Group::AnchoringSeals(v) => v.len(),
        Group::TransLastIdxSigGroups(v) => v.len(),
        Group::DigestSeals(v) | Group::MerkleRootSeals(v) => v.len(),
        Group::LastEventSeals(v) => v.len(),
        Group::BackerSeals(v) => v.len(),
        Group::TypedDigestSeals(v) => v.len(),
        Group::TransIdxSigGroups(v) => v.len(),
        Group::BlindedStates(v) => v.len(),
        Group::BoundStates(v) => v.len(),
        Group::TypedMedia(v) => v.len(),
        _ => return None,
    })
}

/// Whole V2 messages with attachments, text or binary bodies, and the
/// streams of key event logs: parse must consume them, and the values must
/// encode back to the same bytes or to an equivalent stream.
fn streams(r: &mut Runner) {
    for v in [r.load("streams/messages.json"), r.load("kels/kels.json")].concat() {
        let stream = match v["stream"].as_str() {
            Some(s) => s.as_bytes().to_vec(),
            None => hex::decode(field(&v, "stream_hex")).unwrap_or_default(),
        };
        r.check(&field(&v, "id"), move || {
            let values = parse(&stream).map_err(|e| format!("parse error: {e}"))?;
            let text: Vec<u8> = values.iter().flat_map(Value::to_cesr).collect();
            // a stream with binary-domain groups is written back in that domain
            let binary: Vec<u8> = values
                .iter()
                .flat_map(|v| v.to_qb2().unwrap_or_default())
                .collect();
            if text == stream || binary == stream {
                return Ok(());
            }
            // a valid alternative encoding, e.g. a sequence number written as
            // a salt instead of a Number, must still mean the same
            match parse(&text) {
                Ok(again) if again == values => Ok(()),
                _ => Err("re-encoded stream differs".into()),
            }
        });
    }
}

/// Streams in the format of cesrox before 2.0 must convert to the vector's
/// V2 stream.
#[cfg(feature = "legacy-v2beta")]
fn migrations(r: &mut Runner) {
    use cesrox::migrate::{migrate, Options};
    for v in r.load("legacy/migrate.json") {
        let legacy = hex::decode(field(&v, "legacy_hex")).unwrap_or_default();
        let v2 = hex::decode(field(&v, "v2_hex")).unwrap_or_default();
        let wrap = v["wrap_attachments"].as_bool().unwrap_or(true);
        let changed = v["changed"].as_bool();
        r.check(&field(&v, "id"), move || {
            let options = Options {
                wrap_attachments: wrap,
                ..Options::default()
            };
            let migration = migrate(&legacy, &options).map_err(|e| format!("{e}"))?;
            if migration.output != v2 {
                return Err("converted stream differs".into());
            }
            if changed.is_some_and(|c| c != migration.changed) {
                return Err(format!("changed is {}", migration.changed));
            }
            Ok(())
        });
    }
}

/// Input the source rejects must be rejected without panicking. For input it
/// accepts at the edge of the rules only the absence of a panic is checked.
fn negative(r: &mut Runner) {
    for v in r.load("negative/negative.json") {
        let (target, input) = (field(&v, "target"), field(&v, "input"));
        if target == "version" || target == "said" {
            continue; // version strings and SAIDs belong to said
        }
        r.check(&field(&v, "id"), move || {
            if accepts(&target, &input) {
                Err("accepted invalid input".into())
            } else {
                Ok(())
            }
        });
    }
    for v in r.load("negative/edge.json") {
        let (target, input) = (field(&v, "target"), field(&v, "input"));
        if target == "version" || target == "said" {
            continue;
        }
        r.check(&field(&v, "id"), move || {
            accepts(&target, &input);
            Ok(())
        });
    }
}

fn accepts(target: &str, input: &str) -> bool {
    match target {
        "matter" | "stream" => {
            matches!(parse(input.as_bytes()), Ok(values) if !values.is_empty())
        }
        "indexer" => matches!(
            parse_primitive::<AttachedSignatureCode>(input.as_bytes()),
            Ok((_, rest)) if rest.is_empty()
        ),
        "counter" => {
            GroupCode::from_str(input).is_ok()
                || input
                    .get(1..)
                    .is_some_and(|s| UniversalGroupCode::from_str(s).is_ok())
        }
        other => panic!("unknown negative target {other}"),
    }
}
