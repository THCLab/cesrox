//! Checks said against the CESR V2 vectors of every source in
//! `test-vectors/v2`. Known gaps are listed in `vectors_expected_failures.txt`.

#[path = "../../test-vectors/harness.rs"]
mod harness;

use std::str::FromStr;

use harness::{field, Runner};
use said::{
    derivation::{HashFunction, HashFunctionCode},
    sad::SerializationFormats,
    version::SerializationInfo,
    Sad, SelfAddressingIdentifier,
};

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
        digests(&mut r);
        saidify(&mut r);
        version_strings(&mut r);
        negative(&mut r);
    }
    r.finish(EXPECTED, cfg!(feature = "file"));
}

/// Every digest code must give the vector's SAID and round-trip through text.
fn digests(r: &mut Runner) {
    for v in r.load("said/digests.json") {
        let (code, input, qb64) = (field(&v, "code"), field(&v, "input_hex"), field(&v, "qb64"));
        r.check(&field(&v, "id"), move || {
            let code = HashFunctionCode::from_str(&code).map_err(|e| format!("{e:?}"))?;
            let data = hex::decode(input).map_err(|e| e.to_string())?;
            let derived = HashFunction::from(code).derive(&data).to_string();
            if derived != qb64 {
                return Err(format!("derived {derived}"));
            }
            let parsed: SelfAddressingIdentifier = qb64.parse().map_err(|e| format!("{e:?}"))?;
            if parsed.to_string() != qb64 {
                return Err(format!("re-encoded as {parsed}"));
            }
            Ok(())
        });
    }
}

/// Saidified maps and complete messages in every format: computing the
/// SAID into the vector's labels must reproduce the vector's bytes.
fn saidify(r: &mut Runner) {
    for v in r.load("said/saidify.json") {
        let kind = field(&v, "kind");
        let code = field(&v, "code");
        let said = field(&v, "said");
        let labels = labels_of(&v);
        // a map given as JSON, or a complete message in its own format
        let input = match v.get("sad_in_json").and_then(|s| s.as_str()) {
            Some(json) => Input::Json(json.to_string()),
            None => Input::Raw(hex::decode(field(&v, "raw_hex")).unwrap_or_default()),
        };
        let expected = v["sad_out_hex"]
            .as_str()
            .or(v["raw_hex"].as_str())
            .map(|h| hex::decode(h).unwrap_or_default());
        r.check(&field(&v, "id"), move || {
            let format = SerializationFormats::from_str(&kind).map_err(|e| e.to_string())?;
            let code = HashFunctionCode::from_str(&code).map_err(|e| format!("{e:?}"))?;
            let mut sad: Sad = match input {
                Input::Json(json) => serde_json::from_str(&json).map_err(|e| e.to_string())?,
                Input::Raw(raw) => decode(&raw, format)?,
            };
            let labels: Vec<&str> = labels.iter().map(String::as_str).collect();
            let (computed, out) =
                said::saidify(&mut sad, code, format, &labels).map_err(|e| e.to_string())?;
            if computed.to_string() != said {
                return Err(format!("SAID {computed}, expected {said}"));
            }
            match expected {
                Some(expected) if out != expected => Err("serialization differs".into()),
                _ => Ok(()),
            }
        });
    }
}

/// The SAID fields of a vector: `labels`, or the single `label`.
fn labels_of(v: &serde_json::Value) -> Vec<String> {
    match v["labels"].as_array() {
        Some(labels) => labels
            .iter()
            .filter_map(|l| l.as_str())
            .map(String::from)
            .collect(),
        None => vec![field(v, "label")],
    }
}

enum Input {
    Json(String),
    Raw(Vec<u8>),
}

fn decode(raw: &[u8], format: SerializationFormats) -> Result<Sad, String> {
    match format {
        SerializationFormats::JSON => serde_json::from_slice(raw).map_err(|e| e.to_string()),
        SerializationFormats::CBOR => serde_cbor::from_slice(raw).map_err(|e| e.to_string()),
        SerializationFormats::MGPK => rmp_serde::from_slice(raw).map_err(|e| e.to_string()),
        other => Err(format!("cannot read {other:?}")),
    }
}

/// V2 version strings must parse and re-encode identically.
fn version_strings(r: &mut Runner) {
    for v in r.load("said/version_strings.json") {
        let vs = field(&v, "vs");
        r.check(&field(&v, "id"), move || {
            let info = SerializationInfo::from_str(&vs).map_err(|e| e.to_string())?;
            let encoded = info.to_str();
            if encoded != vs {
                return Err(format!("re-encoded as {encoded}"));
            }
            Ok(())
        });
    }
}

/// Version strings and messages whose SAID the source rejects must be
/// rejected without panicking.
fn negative(r: &mut Runner) {
    for v in r.load("negative/negative.json") {
        if field(&v, "target") == "said" {
            let (kind, input) = (field(&v, "kind"), field(&v, "input"));
            let labels = labels_of(&v);
            r.check(&field(&v, "id"), move || {
                let format = SerializationFormats::from_str(&kind).map_err(|e| e.to_string())?;
                let labels: Vec<&str> = labels.iter().map(String::as_str).collect();
                match said::verify(input.as_bytes(), format, &labels) {
                    Ok(_) => Err("verified an invalid SAID".into()),
                    Err(_) => Ok(()),
                }
            });
            continue;
        }
        if field(&v, "target") != "version" {
            continue;
        }
        let input = field(&v, "input");
        r.check(
            &field(&v, "id"),
            move || match SerializationInfo::from_str(&input) {
                Ok(_) => Err("accepted invalid version string".into()),
                Err(_) => Ok(()),
            },
        );
    }
    for v in r.load("negative/edge.json") {
        if field(&v, "target") != "version" {
            continue;
        }
        let input = field(&v, "input");
        r.check(&field(&v, "id"), move || {
            let _ = SerializationInfo::from_str(&input);
            Ok(())
        });
    }
}
