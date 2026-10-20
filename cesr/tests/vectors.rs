//! Checks cesrox against the keripy-generated CESR V2 vectors in
//! `test-vectors/v2`. Known gaps are listed in `vectors_expected_failures.txt`.

#[path = "../../test-vectors/harness.rs"]
mod harness;

use std::str::FromStr;

use cesrox::{
    derivation_code::DerivationCode,
    group::codes::GroupCode,
    parse, parse_value,
    primitives::{codes::attached_signature_code::AttachedSignatureCode, parse_primitive},
    universal_codes::UniversalGroupCode,
    value::Value,
};
use harness::{field, Runner};

const EXPECTED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors_expected_failures.txt"
);

#[test]
fn keripy_v2_vectors() {
    let Some(mut r) = Runner::new(env!("CARGO_MANIFEST_DIR")) else {
        return;
    };
    primitives(&mut r);
    indexed(&mut r);
    counters(&mut r);
    streams(&mut r);
    negative(&mut r);
    r.finish(EXPECTED, cfg!(feature = "cesr-proof"));
}

/// parse_value must consume the primitive, report keripy's code and raw bytes,
/// and re-encode to the same text.
fn primitives(r: &mut Runner) {
    for file in [
        "primitives/fixed.json",
        "primitives/variable.json",
        "primitives/special.json",
    ] {
        for v in r.load(file) {
            let (qb64, code, raw) = (field(&v, "qb64"), field(&v, "code"), field(&v, "raw_hex"));
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
                match &val {
                    Value::Primitive(c, bytes) => {
                        if c.to_str() != code {
                            return Err(format!("code {} != {code}", c.to_str()));
                        }
                        if hex::encode(bytes) != raw {
                            return Err(format!("raw {} != {raw}", hex::encode(bytes)));
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

/// Indexed signatures: code, index, ondex and raw bytes as keripy's Indexer.
fn indexed(r: &mut Runner) {
    for v in r.load("indexed/indexers.json") {
        let (qb64, raw) = (field(&v, "qb64"), field(&v, "raw_hex"));
        let index = v["index"].as_u64().unwrap_or_default();
        let ondex = v["ondex"].as_u64();
        r.check(&field(&v, "id"), move || {
            let ((c, bytes), rest) = parse_primitive::<AttachedSignatureCode>(qb64.as_bytes())
                .map_err(|e| format!("parse error: {e}"))?;
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
            Ok(())
        });
    }
}

/// Counters: code and count must parse and re-encode identically.
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
            if matches!(b.get(1), Some(b'A' | b'B' | b'C' | b'E')) {
                let c = UniversalGroupCode::from_str(&qb64[1..])
                    .map_err(|e| format!("parse error: {e}"))?;
                return if c.value_size() as u64 == count {
                    Ok(())
                } else {
                    Err(format!("count {} != {count}", c.value_size()))
                };
            }
            let c = GroupCode::from_str(&qb64).map_err(|e| format!("unsupported: {e}"))?;
            if c.to_str() != qb64 {
                return Err(format!("re-encoded as {}", c.to_str()));
            }
            Ok(())
        });
    }
}

/// Whole keripy V2 messages with attachments, text or binary bodies: parse
/// must consume them.
fn streams(r: &mut Runner) {
    for v in r.load("streams/messages.json") {
        let stream = match v["stream"].as_str() {
            Some(s) => s.as_bytes().to_vec(),
            None => hex::decode(field(&v, "stream_hex")).unwrap_or_default(),
        };
        r.check(&field(&v, "id"), move || {
            parse(&stream).map_err(|e| format!("parse error: {e}"))?;
            Ok(())
        });
    }
}

/// Input keripy rejects must be rejected without panicking. For input keripy
/// accepts at the edge of the rules only the absence of a panic is checked.
fn negative(r: &mut Runner) {
    for v in r.load("negative/negative.json") {
        let (target, input) = (field(&v, "target"), field(&v, "input"));
        if target == "version" {
            continue; // version strings belong to said
        }
        r.check(&field(&v, "id"), move || {
            if accepts(&target, &input) {
                Err("accepted invalid input".into())
            } else {
                Ok(())
            }
        });
    }
    for v in r.load("negative/keripy_accepts_edge.json") {
        let (target, input) = (field(&v, "target"), field(&v, "input"));
        if target == "version" {
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
