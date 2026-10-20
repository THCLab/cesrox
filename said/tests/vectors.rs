//! Checks said against the keripy-generated CESR V2 vectors in
//! `test-vectors/v2`. Known gaps are listed in `vectors_expected_failures.txt`.

#[path = "../../test-vectors/harness.rs"]
mod harness;

use std::str::FromStr;

use harness::{field, Runner};
use said::{
    derivation::{HashFunction, HashFunctionCode},
    make_me_happy,
    version::SerializationInfo,
    SelfAddressingIdentifier,
};

const EXPECTED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors_expected_failures.txt"
);

#[test]
fn keripy_v2_vectors() {
    let Some(mut r) = Runner::new(env!("CARGO_MANIFEST_DIR")) else {
        return;
    };
    digests(&mut r);
    saidify(&mut r);
    version_strings(&mut r);
    negative(&mut r);
    r.finish(EXPECTED, cfg!(any(feature = "macros", feature = "file")));
}

/// Every digest code must give keripy's SAID and round-trip through text.
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

/// SADs saidified by keripy. said can only saidify JSON maps given as text,
/// so the CBOR and MGPK cases fail until it can.
fn saidify(r: &mut Runner) {
    for v in r.load("said/saidify.json") {
        let id = field(&v, "id");
        let kind = field(&v, "kind");
        let code = field(&v, "code");
        let said = field(&v, "said");
        // JSON input and the expected output, when said has a way to compute it
        let case = if kind != "JSON" {
            Err(format!("no said API to saidify a {kind} map"))
        } else if let Some(sad) = v.get("sad_in_json").and_then(|s| s.as_str()) {
            let out = v["sad_out_hex"]
                .as_str()
                .map(|h| String::from_utf8(hex::decode(h).unwrap()).unwrap());
            Ok((sad.to_string(), out))
        } else {
            // a complete keripy message: re-deriving its SAID must reproduce it
            let raw = String::from_utf8(hex::decode(field(&v, "raw_hex")).unwrap()).unwrap();
            Ok((raw.clone(), Some(raw)))
        };
        r.check(&id, move || {
            let (sad, expected) = case?;
            let code = HashFunctionCode::from_str(&code).map_err(|e| format!("{e:?}"))?;
            let out = make_me_happy(&sad, code, None).map_err(|e| format!("{e:?}"))?;
            match expected {
                Some(expected) if out != expected => Err(format!("got {out}")),
                None if !out.contains(&said) => Err(format!("SAID {said} not in {out}")),
                _ => Ok(()),
            }
        });
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

/// Version strings keripy rejects must be rejected without panicking.
fn negative(r: &mut Runner) {
    for v in r.load("negative/negative.json") {
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
    for v in r.load("negative/keripy_accepts_edge.json") {
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
