//! Writes the CESR V2 test vectors of the cesrox source: the streams,
//! groups, SAIDs and conversions of the old cesrox format that cesrox and
//! said produce, for other implementations to test against.
//!
//! Usage: `cargo run -p cesrox-vectors -- <out_dir>`, see `generate.sh`.
//!
//! Everything is deterministic: keys and filler bytes are derived from
//! labels, so the same code always writes the same files. Signatures are
//! real Ed25519 signatures over the message bodies; the keys of each
//! message are listed with it.

use std::{collections::BTreeMap, fs, path::Path};

use cesrox::{
    group::Group,
    migrate::{migrate, Options},
    parse,
    payload::Payload,
    primitives::{
        codes::{
            attached_signature_code::{AttachedSignatureCode, Index},
            basic::Basic,
            self_addressing::SelfAddressing,
            self_signing::SelfSigning,
            TagCode,
        },
        AnchoringEventSeal, Digest, Identifier, IdentifierCode, IndexedSignature, PublicKey,
        Signature,
    },
    universal_codes::UniversalCode,
    Value,
};
use ed25519_dalek::{Signer as _, SigningKey};
use said::{
    derivation::{HashFunction, HashFunctionCode},
    sad::DerivationCode,
    sad::SerializationFormats,
    saidify, Sad,
};
use serde_json::{json, Value as Json};

const TOOL_VERSION: &str = "0.1.0";

fn main() {
    let out = std::env::args()
        .nth(1)
        .expect("usage: cesrox-vectors <out_dir>");
    let generator = json!({
        "tool": "cesrox-vectors",
        "version": TOOL_VERSION,
        "source": {
            "implementation": "cesrox",
            // the vectors are committed with the code that writes them
            "revision": "the commit that contains these files",
            "version": "2",
        },
    });

    let files: Vec<(&str, &str, Vec<Json>)> = vec![
        ("groups/groups.json", "group/1", groups()),
        ("streams/messages.json", "stream/1", streams()),
        ("said/saidify.json", "saidify/1", saidified()),
        ("legacy/migrate.json", "migrate/1", migrations()),
        ("negative/negative.json", "negative/1", negative()),
    ];

    let out = Path::new(&out);
    let mut counts = BTreeMap::new();
    for (rel, schema, vectors) in files {
        let mut ids: Vec<&str> = vectors.iter().map(|v| v["id"].as_str().unwrap()).collect();
        ids.sort();
        if let Some(pair) = ids.windows(2).find(|p| p[0] == p[1]) {
            panic!("{rel}: duplicate vector id {}", pair[0]);
        }
        counts.insert(rel, vectors.len());
        write(
            &out.join(rel),
            &json!({"schema": schema, "generator": generator, "vectors": vectors}),
        );
    }
    write(
        &out.join("manifest.json"),
        &json!({"files": counts, "generator": generator}),
    );
}

fn write(path: &Path, value: &Json) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut text = serde_json::to_string_pretty(value).unwrap();
    text.push('\n');
    fs::write(path, text).unwrap();
}

// --------------------------------------------------------------------------
// deterministic material
// --------------------------------------------------------------------------

/// `n` bytes derived from `label`.
fn det_bytes(label: &str, n: usize) -> Vec<u8> {
    let sha = HashFunction::from(HashFunctionCode::SHA2_512);
    let mut out = Vec::new();
    let mut i = 0;
    while out.len() < n {
        out.extend(sha.digest(format!("{label}/{i}").as_bytes()));
        i += 1;
    }
    out.truncate(n);
    out
}

struct Key(SigningKey);

impl Key {
    fn new(label: &str) -> Self {
        Key(SigningKey::from_bytes(
            &det_bytes(&format!("key/{label}"), 32).try_into().unwrap(),
        ))
    }

    fn public(&self, code: Basic) -> PublicKey {
        PublicKey::new(code, self.0.verifying_key().to_bytes().to_vec())
    }

    /// Transferable public key, `D`.
    fn qb64(&self) -> String {
        Value::Primitive(self.public(Basic::Ed25519).into_value_primitive()).to_string()
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.0.sign(data).to_bytes().to_vec()
    }

    fn signature(&self, data: &[u8]) -> Signature {
        Signature::new(SelfSigning::Ed25519Sha512, self.sign(data))
    }

    fn indexed(&self, data: &[u8], index: Index) -> IndexedSignature {
        IndexedSignature::new(
            AttachedSignatureCode::new(SelfSigning::Ed25519Sha512, index),
            self.sign(data),
        )
    }
}

trait IntoValuePrimitive {
    fn into_value_primitive(
        self,
    ) -> cesrox::primitives::Primitive<cesrox::primitives::codes::PrimitiveCode>;
}

impl<C: Into<cesrox::primitives::codes::PrimitiveCode>> IntoValuePrimitive
    for cesrox::primitives::Primitive<C>
{
    fn into_value_primitive(
        self,
    ) -> cesrox::primitives::Primitive<cesrox::primitives::codes::PrimitiveCode> {
        cesrox::primitives::Primitive::new(self.code.into(), self.raw)
    }
}

fn digest(label: &str) -> Digest {
    Digest::new(
        SelfAddressing::Blake3_256,
        HashFunction::from(HashFunctionCode::Blake3_256).digest(label.as_bytes()),
    )
}

fn prefix(label: &str) -> Identifier {
    Identifier::new(
        IdentifierCode::SelfAddressing(SelfAddressing::Blake3_256),
        digest(label).raw,
    )
}

fn timestamp(text: &str) -> cesrox::primitives::Timestamp {
    chrono::DateTime::parse_from_rfc3339(text).unwrap()
}

fn group(g: Group) -> Value {
    Value::SpecificGroup(g)
}

fn attachments(groups: Vec<Group>) -> Value {
    Value::universal_group(
        UniversalCode::Attachments,
        groups.into_iter().map(group).collect(),
    )
    .unwrap()
}

fn tag(text: &str) -> Value {
    Value::Tag(TagCode::new(text).unwrap())
}

fn number(n: u128) -> Value {
    one(&cesrox::primitives::codes::number::pack_number(n))
}

/// The single value `text` is.
fn one(text: &str) -> Value {
    let mut values = parse(text.as_bytes()).unwrap();
    assert_eq!(values.len(), 1, "{text}");
    values.remove(0)
}

fn text(value: &Value) -> String {
    String::from_utf8(value.to_cesr()).unwrap()
}

// --------------------------------------------------------------------------
// messages
// --------------------------------------------------------------------------

fn format_of(kind: &str) -> SerializationFormats {
    kind.parse().unwrap()
}

fn payload(kind: &str, bytes: Vec<u8>) -> Payload {
    match kind {
        "JSON" => Payload::JSON(bytes),
        "CBOR" => Payload::CBOR(bytes),
        "MGPK" => Payload::MGPK(bytes),
        other => panic!("no payload kind {other}"),
    }
}

fn sad(value: Json) -> Sad {
    serde_json::from_value(value).unwrap()
}

/// A saidified KERI V2 message in `kind`: the SAID and the bytes.
fn message(kind: &str, value: Json, labels: &[&str]) -> (String, Vec<u8>) {
    let mut map = sad(value);
    let (said, bytes) = saidify(
        &mut map,
        HashFunctionCode::Blake3_256,
        format_of(kind),
        labels,
    )
    .unwrap();
    (said.to_string(), bytes)
}

fn version(kind: &str) -> String {
    format!("KERICAACAA{kind}AAAA.")
}

/// An inception event with three keys and its own SAID as identifier.
fn inception(kind: &str, keys: &[Key]) -> (String, Vec<u8>) {
    message(kind, inception_map(kind, keys), &["d", "i"])
}

/// An inception event with empty SAID fields.
fn inception_map(kind: &str, keys: &[Key]) -> Json {
    let next: Vec<String> = keys
        .iter()
        .map(|k| {
            let d = HashFunction::from(HashFunctionCode::Blake3_256).derive(k.qb64().as_bytes());
            d.to_string()
        })
        .collect();
    json!({
        "v": version(kind), "t": "icp", "d": "", "i": "", "s": "0", "kt": "2",
        "k": keys.iter().map(Key::qb64).collect::<Vec<_>>(),
        "nt": "2", "n": next, "bt": "0", "b": [], "c": [], "a": [],
    })
}

fn interaction(prefix: &str, prior: &str) -> (String, Vec<u8>) {
    message(
        "JSON",
        json!({
            "v": version("JSON"), "t": "ixn", "d": "", "i": prefix, "s": "1", "p": prior,
            "a": [{"i": prefix, "s": "0", "d": prior}],
        }),
        &["d"],
    )
}

fn receipt(prefix: &str, said: &str) -> Vec<u8> {
    let mut map = sad(json!({
        "v": version("JSON"), "t": "rct", "d": said, "i": prefix, "s": "0",
    }));
    // the size field has a fixed width, so setting it keeps the size
    let mut info: said::version::SerializationInfo = version("JSON").parse().unwrap();
    info.size = serde_json::to_vec(&map).unwrap().len();
    map.insert("v".into(), info.to_str().into());
    serde_json::to_vec(&map).unwrap()
}

fn controller_signatures(keys: &[Key], body: &[u8]) -> Group {
    Group::IndexedControllerSignatures(
        keys.iter()
            .enumerate()
            .map(|(i, k)| k.indexed(body, Index::BothSame(i as u32)))
            .collect(),
    )
}

fn keys(label: &str, n: usize) -> Vec<Key> {
    (0..n).map(|i| Key::new(&format!("{label}/{i}"))).collect()
}

fn stream_vector(id: &str, stream: &[u8], keys: &[Key], note: &str) -> Json {
    let mut v = json!({"id": id, "note": note});
    match std::str::from_utf8(stream) {
        Ok(text) => v["stream"] = text.into(),
        Err(_) => v["stream_hex"] = hex::encode(stream).into(),
    }
    if !keys.is_empty() {
        v["sigs_verkeys"] = keys.iter().map(Key::qb64).collect::<Vec<_>>().into();
    }
    v
}

fn streams() -> Vec<Json> {
    let mut vectors = vec![];
    let signers = keys("stream", 3);

    // a signed inception in every non-native format, attachments wrapped
    // in -C, in the text and in the binary domain
    for kind in ["JSON", "CBOR", "MGPK"] {
        let (_, body) = inception(kind, &signers);
        let atts = attachments(vec![controller_signatures(&signers, &body)]);
        let body_value = Value::Payload(payload(kind, body.clone()));
        vectors.push(stream_vector(
            &format!("stream/icp/{kind}/attachments"),
            &[body_value.to_cesr(), atts.to_cesr()].concat(),
            &signers,
            "inception, three indexed controller signatures in an attachment group",
        ));
        vectors.push(stream_vector(
            &format!("stream/icp/{kind}/attachments-qb2"),
            &[body_value.to_cesr(), atts.to_qb2().unwrap()].concat(),
            &signers,
            "as stream/icp/<kind>/attachments, attachments in the binary domain",
        ));
    }

    // a key event log: inception, interaction and a witness receipt
    let (icp_said, icp) = inception("JSON", &signers);
    let (_, ixn) = interaction(&icp_said, &icp_said);
    let witness = Key::new("stream/witness");
    let rct = receipt(&icp_said, &icp_said);
    let kel = [
        icp.clone(),
        attachments(vec![controller_signatures(&signers, &icp)]).to_cesr(),
        ixn.clone(),
        attachments(vec![controller_signatures(&signers, &ixn)]).to_cesr(),
        rct,
        attachments(vec![Group::NontransReceiptCouples(vec![
            cesrox::group::NontransReceiptCouple {
                key: witness.public(Basic::Ed25519Nontrans),
                signature: witness.signature(&icp),
            },
        ])])
        .to_cesr(),
    ]
    .concat();
    vectors.push(stream_vector(
        "stream/kel/JSON/icp-ixn-rct",
        &kel,
        &signers,
        "three messages: inception, interaction anchoring a seal, and a receipt by a \
         non-transferable witness whose key is in the receipt couple",
    ));

    // text and binary attachments alternating between messages
    let text_atts = attachments(vec![controller_signatures(&signers, &icp)]);
    let ixn_atts = attachments(vec![controller_signatures(&signers, &ixn)]);
    vectors.push(stream_vector(
        "stream/kel/JSON/mixed-domains",
        &[
            icp.clone(),
            text_atts.to_qb2().unwrap(),
            ixn.clone(),
            ixn_atts.to_cesr(),
        ]
        .concat(),
        &signers,
        "binary-domain attachments after the first message, text after the second",
    ));

    // a genus/version code before the stream
    vectors.push(stream_vector(
        "stream/icp/JSON/genus",
        &[b"-_AAACAA".to_vec(), icp.clone(), text_atts.to_cesr()].concat(),
        &signers,
        "KERI/ACDC genus version 2.0 code before the message",
    ));

    // signatures by other transferable identifiers and seals
    let endorser = keys("stream/endorser", 2);
    let endorsements = attachments(vec![
        controller_signatures(&signers, &icp),
        Group::TransIdxSigGroups(vec![cesrox::group::TransIdxSigGroup {
            prefix: prefix("endorser"),
            sn: 0,
            digest: digest("endorser/icp"),
            signatures: endorser
                .iter()
                .enumerate()
                .map(|(i, k)| k.indexed(&icp, Index::BothSame(i as u32)))
                .collect(),
        }]),
        Group::TransLastIdxSigGroups(vec![cesrox::group::TransLastIdxSigGroup {
            prefix: prefix("endorser"),
            signatures: vec![endorser[1].indexed(&icp, Index::CurrentOnly(1))],
        }]),
        Group::AnchoringSeals(vec![AnchoringEventSeal {
            prefix: prefix("delegator"),
            sn: 4,
            digest: digest("delegator/ixn"),
        }]),
        Group::FirstSeenReplayCouples(vec![cesrox::group::FirstSeenReplayCouple {
            fnu: 0,
            timestamp: timestamp("2024-01-01T00:00:00.000000+00:00"),
        }]),
    ]);
    vectors.push(stream_vector(
        "stream/icp/JSON/endorsed",
        &[icp.clone(), endorsements.to_cesr()].concat(),
        &signers,
        "attachment group with -K, -X, -Y, -T and -O groups; the -X and -Y \
         signatures are by keys not listed with the message",
    ));

    // a non-native body enclosed in -H, and a native field map
    let enclosed = Value::non_native_body(&Payload::JSON(icp.clone())).unwrap();
    vectors.push(stream_vector(
        "stream/icp/JSON/enclosed",
        &[enclosed.to_cesr(), text_atts.to_cesr()].concat(),
        &signers,
        "the JSON message enclosed as a non-native body group (-H), then its attachments",
    ));
    let map = Value::universal_group(
        UniversalCode::GenericMap,
        vec![
            tag("t"),
            tag("icp"),
            tag("s"),
            number(0),
            tag("k"),
            Value::universal_group(
                UniversalCode::GenericList,
                signers
                    .iter()
                    .map(|k| Value::Primitive(k.public(Basic::Ed25519).into_value_primitive()))
                    .collect(),
            )
            .unwrap(),
            tag("d"),
            Value::Primitive(digest("map").into_value_primitive()),
        ],
    )
    .unwrap();
    let generic = Value::universal_group(UniversalCode::GenericGroup, vec![map]).unwrap();
    vectors.push(stream_vector(
        "stream/native/generic-map",
        &generic.to_cesr(),
        &[],
        "a generic group (-A) holding a field map (-I) of tags, a number, a list (-J) \
         of keys and a digest",
    ));

    // a group too large for a small count
    let many = keys("stream/many", 1);
    let big = attachments(vec![Group::IndexedControllerSignatures(
        (0..190)
            .map(|i| many[0].indexed(&icp, Index::CurrentOnly(i)))
            .collect(),
    )]);
    vectors.push(stream_vector(
        "stream/icp/JSON/big-attachments",
        &[icp, big.to_cesr()].concat(),
        &[],
        "190 indexed signatures, more than 4095 quadlets: big counters --C and --K, \
         small and big current-only codes",
    ));
    vectors
}

// --------------------------------------------------------------------------
// groups
// --------------------------------------------------------------------------

fn group_vector(id: &str, items: usize, g: Group) -> Json {
    json!({
        "id": format!("group/{id}"),
        "items": items,
        "qb64": g.to_cesr_str(),
        "qb2_hex": hex::encode(g.to_qb2().unwrap()),
    })
}

fn groups() -> Vec<Json> {
    let signers = keys("group", 2);
    let data = b"group vectors";
    let sig = |i: usize, index: Index| signers[i % 2].indexed(data, index);
    vec![
        group_vector(
            "ControllerIdxSigs/indexes",
            6,
            Group::IndexedControllerSignatures(vec![
                sig(0, Index::BothSame(0)),
                sig(1, Index::BothSame(63)),
                sig(0, Index::BothSame(64)),
                sig(1, Index::Dual(2, 5)),
                sig(0, Index::CurrentOnly(3)),
                sig(1, Index::CurrentOnly(4095)),
            ]),
        ),
        group_vector(
            "WitnessIdxSigs/current-only",
            2,
            Group::IndexedWitnessSignatures(vec![
                sig(0, Index::CurrentOnly(0)),
                sig(1, Index::CurrentOnly(70)),
            ]),
        ),
        group_vector(
            "ControllerIdxSigs/big-count",
            190,
            Group::IndexedControllerSignatures(
                (0..190)
                    .map(|i| sig(i, Index::BothSame(i as u32)))
                    .collect(),
            ),
        ),
        group_vector(
            "SealSourceCouples/big-sn",
            2,
            Group::SourceSealCouples(vec![
                cesrox::group::SealSourceCouple {
                    sn: 0,
                    digest: digest("s0"),
                },
                cesrox::group::SealSourceCouple {
                    sn: u128::from(u64::MAX) + 1,
                    digest: digest("s1"),
                },
            ]),
        ),
        group_vector(
            "SealSourceTriples/two",
            2,
            Group::AnchoringSeals(vec![
                AnchoringEventSeal {
                    prefix: prefix("t0"),
                    sn: 1,
                    digest: digest("t0/1"),
                },
                AnchoringEventSeal {
                    prefix: prefix("t1"),
                    sn: 300,
                    digest: digest("t1/300"),
                },
            ]),
        ),
        group_vector(
            "TransIdxSigGroups/two",
            2,
            Group::TransIdxSigGroups(
                (0..2)
                    .map(|n| cesrox::group::TransIdxSigGroup {
                        prefix: prefix(&format!("x{n}")),
                        sn: n as u128,
                        digest: digest(&format!("x{n}")),
                        signatures: vec![sig(0, Index::BothSame(0)), sig(1, Index::BothSame(1))],
                    })
                    .collect(),
            ),
        ),
        group_vector(
            "TransLastIdxSigGroups/two",
            2,
            Group::TransLastIdxSigGroups(
                (0..2)
                    .map(|n| cesrox::group::TransLastIdxSigGroup {
                        prefix: prefix(&format!("y{n}")),
                        signatures: vec![sig(n, Index::CurrentOnly(n as u32))],
                    })
                    .collect(),
            ),
        ),
        group_vector(
            "NonTransReceiptCouples/two",
            2,
            Group::NontransReceiptCouples(
                signers
                    .iter()
                    .map(|k| cesrox::group::NontransReceiptCouple {
                        key: k.public(Basic::Ed25519Nontrans),
                        signature: k.signature(data),
                    })
                    .collect(),
            ),
        ),
        group_vector(
            "FirstSeenReplayCouples/two",
            2,
            Group::FirstSeenReplayCouples(vec![
                cesrox::group::FirstSeenReplayCouple {
                    fnu: 1,
                    timestamp: timestamp("2020-08-22T17:50:09.988921+00:00"),
                },
                cesrox::group::FirstSeenReplayCouple {
                    fnu: 70000,
                    timestamp: timestamp("2024-12-31T23:59:59.000000+00:00"),
                },
            ]),
        ),
        group_vector(
            "SealSourceLastSingles/two",
            2,
            Group::LastEventSeals(vec![prefix("u0"), prefix("u1")]),
        ),
        group_vector(
            "BackerRegistrarSealCouples/one",
            1,
            Group::BackerSeals(vec![cesrox::group::BackerSeal {
                prefix: prefix("backer"),
                digest: digest("registrar"),
            }]),
        ),
        group_vector(
            "DigestSealSingles/three",
            3,
            Group::DigestSeals(vec![digest("a"), digest("b"), digest("c")]),
        ),
    ]
}

// --------------------------------------------------------------------------
// SAIDs
// --------------------------------------------------------------------------

fn saidify_vector(
    id: &str,
    code: HashFunctionCode,
    kind: &str,
    labels: &[&str],
    input: Json,
) -> Json {
    let mut map = sad(input.clone());
    let (said, out) = saidify(&mut map, code.clone(), format_of(kind), labels).unwrap();
    // the SAID fields hold placeholders of its length while it is computed;
    // the version string, if any, already has its final size
    let mut dummy = map.clone();
    for label in labels {
        dummy.insert((*label).into(), "#".repeat(said.to_string().len()).into());
    }
    let derivation = format_of(kind).encode(&dummy).unwrap();
    assert!(said.verify_binding(&derivation));
    json!({
        "id": format!("saidify/{id}"),
        "code": code.to_str(),
        "kind": kind,
        "label": labels[0],
        "labels": labels,
        "sad_in_json": serde_json::to_string(&input).unwrap(),
        "said": said.to_string(),
        "derivation_input_hex": hex::encode(derivation),
        "sad_out_hex": hex::encode(out),
    })
}

fn saidified() -> Vec<Json> {
    let mut vectors = vec![];
    let e = HashFunctionCode::Blake3_256;
    for kind in ["JSON", "CBOR", "MGPK"] {
        vectors.push(saidify_vector(
            &format!("self-addressing/{kind}"),
            e.clone(),
            kind,
            &["d", "i"],
            inception_map(kind, &keys("saidify", 2)),
        ));
        vectors.push(saidify_vector(
            &format!("v1-version/{kind}"),
            e.clone(),
            kind,
            &["d"],
            json!({"v": format!("KERI10{kind}000000_"), "t": "rpy", "d": "", "a": {"x": 1}}),
        ));
        vectors.push(saidify_vector(
            &format!("nested/{kind}"),
            e.clone(),
            kind,
            &["d"],
            json!({
                "v": format!("ACDCCAACAA{kind}AAAA."), "d": "", "u": "0AAa",
                "a": {"d": "", "n": [0, 1, 255, 65536, 4294967296u64], "neg": -1,
                      "text": "zażółć gęślą jaźń", "empty": {}, "list": [[], [{}]], "t": true,
                      "f": false, "null": null},
            }),
        ));
    }
    for code in [
        HashFunctionCode::Blake2B256,
        HashFunctionCode::Blake2S256,
        HashFunctionCode::SHA3_256,
        HashFunctionCode::SHA2_256,
        HashFunctionCode::Blake3_512,
        HashFunctionCode::Blake2B512,
        HashFunctionCode::SHA3_512,
        HashFunctionCode::SHA2_512,
    ] {
        vectors.push(saidify_vector(
            &format!("code/{}", code.to_str()),
            code.clone(),
            "JSON",
            &["d"],
            json!({"v": version("JSON"), "d": "", "text": "Hello world"}),
        ));
    }
    vectors
}

// --------------------------------------------------------------------------
// the format of cesrox before 2.0
// --------------------------------------------------------------------------

fn migration_vector(id: &str, legacy: &[u8], wrap: bool, note: &str) -> Json {
    let options = Options {
        wrap_attachments: wrap,
        ..Options::default()
    };
    let migration = migrate(legacy, &options).unwrap();
    json!({
        "id": format!("migrate/{id}"),
        "legacy_hex": hex::encode(legacy),
        "v2_hex": hex::encode(&migration.output),
        "wrap_attachments": wrap,
        "changed": migration.changed,
        "note": note,
    })
}

fn migrations() -> Vec<Json> {
    let kel = include_bytes!("../../../../cesr/tests/data/legacy_kel.cesr");
    let signers = keys("legacy", 2);
    let (said, icp) = inception("JSON", &signers);
    let sigs = controller_signatures(&signers, &icp);
    let seals = Group::SourceSealCouples(vec![cesrox::group::SealSourceCouple {
        sn: 1,
        digest: digest("source"),
    }]);
    let legacy = [
        icp.clone(),
        sigs.to_legacy_cesr_str().into_bytes(),
        seals.to_legacy_cesr_str().into_bytes(),
    ]
    .concat();
    let v2 = migrate(&legacy, &Options::default()).unwrap().output;
    let receipt = [
        receipt(&said, &said),
        Group::NontransReceiptCouples(vec![cesrox::group::NontransReceiptCouple {
            key: signers[0].public(Basic::Ed25519Nontrans),
            signature: signers[0].signature(&icp),
        }])
        .to_legacy_cesr_str()
        .into_bytes(),
    ]
    .concat();
    vec![
        migration_vector(
            "kel/wrapped",
            kel,
            true,
            "a two-event KEL with controller signatures and witness receipts as \
             cesrox wrote it before 2.0",
        ),
        migration_vector(
            "kel/bare",
            kel,
            false,
            "as migrate/kel/wrapped, groups not wrapped",
        ),
        migration_vector(
            "icp/signatures-and-seal",
            &legacy,
            true,
            "item-counted -K and -S groups; the old -S writes the sequence number as a salt",
        ),
        migration_vector(
            "rct/receipt-couple",
            &receipt,
            true,
            "item-counted -M group",
        ),
        migration_vector("v2/unchanged", &v2, true, "V2 input is returned unchanged"),
    ]
}

// --------------------------------------------------------------------------
// input that must be rejected
// --------------------------------------------------------------------------

fn reject(target: &str, why: &str, input: &str) -> Json {
    json!({
        "id": format!("neg/{target}/{why}"),
        "target": target,
        "input": input,
        "why": why,
        "source_accepts": false,
    })
}

/// An inception event, whose SAID is in `d` and `i`, that must not verify.
fn reject_said(why: &str, input: &[u8]) -> Json {
    let mut v = reject("said", why, std::str::from_utf8(input).unwrap());
    v["kind"] = "JSON".into();
    v["labels"] = json!(["d", "i"]);
    v
}

fn negative() -> Vec<Json> {
    let signers = keys("negative", 1);
    let d = text(&Value::Primitive(digest("x").into_value_primitive()));
    let sig = text(&group(Group::IndexedControllerSignatures(vec![
        signers[0].indexed(b"x", Index::BothSame(0))
    ])));
    let (_, icp) = inception("JSON", &keys("negative/icp", 2));
    let icp = String::from_utf8(icp).unwrap();
    let icp_i = &icp[icp.find(r#""i":""#).unwrap() + 5..][..44];

    let mut vectors = vec![
        reject("matter", "pad-equals", &format!("{}=", &d[..43])),
        // a one-character code stands in for the first six bits of a lead
        // zero byte; the other two are the top bits of the next character
        reject("matter", "nonzero-lead-pad-bits", &format!("E_{}", &d[2..])),
        reject(
            "matter",
            "lowercase-selector-digest",
            &format!("e{}", &d[1..]),
        ),
        reject("stream", "group-count-short", &format!("-KAV{}", &sig[4..])),
        reject("stream", "group-count-long", &format!("-KAX{}", &sig[4..])),
        reject("stream", "attachments-count-short", &format!("-CAV{sig}")),
        reject("stream", "group-item-not-a-signature", &format!("-KAL{d}")),
        reject("stream", "truncated-body", &icp[..icp.len() - 1]),
        reject("counter", "big-count-truncated", "--KAAA"),
        reject("version", "v1-no-terminator", "KERI10JSON00014b"),
        reject("version", "v1-size-not-hex", "KERI10JSON00014g_"),
        reject("version", "v1-major-not-hex", "KERIx0JSON00014b_"),
        reject("version", "v2-size-short", "KERICAACAAJSONAAB."),
    ];

    // inceptions whose SAID must not verify
    vectors.push(reject_said(
        "changed-content",
        icp.replace(r#""kt":"2""#, r#""kt":"1""#).as_bytes(),
    ));
    vectors.push(reject_said(
        "not-compact",
        icp.replace(r#","kt""#, r#", "kt""#).as_bytes(),
    ));
    vectors.push(reject_said(
        "fields-disagree",
        icp.replacen(icp_i, &d, 1).as_bytes(),
    ));
    let mut wrong_size = icp.clone();
    let end = wrong_size.find('.').unwrap();
    let last = if &wrong_size[end - 1..end] == "A" {
        "B"
    } else {
        "A"
    };
    wrong_size.replace_range(end - 1..end, last);
    vectors.push(reject_said("version-size-wrong", wrong_size.as_bytes()));
    vectors
}
