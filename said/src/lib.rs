pub mod cesr_adapter;
pub mod derivation;
pub mod error;
pub mod sad;
pub mod version;

use core::{fmt, str::FromStr};

use cesrox::{derivation_code::DerivationCode, primitives::CesrPrimitive};
use indexmap::IndexMap;
use sad::SerializationFormats;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use version::{error::Error, SerializationInfo};

use self::derivation::HashFunction;
use crate::derivation::HashFunctionCode;

/// Self Addressing Identifier
///
/// Self-addressing is a digest/hash of data.
#[derive(PartialEq, Clone, Hash, Eq, Default)]
pub struct SelfAddressingIdentifier {
    /// Hash algorithm used for computing digest
    pub derivation: HashFunction,
    /// Computed digest
    pub digest: Vec<u8>,
}

impl fmt::Debug for SelfAddressingIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.to_str())
    }
}

impl SelfAddressingIdentifier {
    pub fn new(code: HashFunction, digest: Vec<u8>) -> Self {
        Self {
            derivation: code,
            digest,
        }
    }

    pub fn verify_binding(&self, sed: &[u8]) -> bool {
        self.derivation.digest(sed) == self.digest
    }
}

impl fmt::Display for SelfAddressingIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

/// Serde compatible Serialize
impl Serialize for SelfAddressingIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str())
    }
}

/// Serde compatible Deserialize
impl<'de> Deserialize<'de> for SelfAddressingIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<SelfAddressingIdentifier, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        SelfAddressingIdentifier::from_str(&s).map_err(serde::de::Error::custom)
    }
}

pub struct ProtocolVersion {
    pub(crate) prefix: String,
    pub(crate) major: u8,
    pub(crate) minor: u16,
}

impl ProtocolVersion {
    pub fn new(prefix: &str, major: u8, minor: u16) -> Result<Self, Error> {
        if prefix.len() == 4 {
            Ok(Self {
                prefix: prefix.to_string(),
                major,
                minor,
            })
        } else {
            Err(Error::VersionStringLength(prefix.to_string()))
        }
    }
}

/// A self-addressing data map. Field order is kept as given, because the
/// serialization the SAID is computed over depends on it.
pub type Sad = IndexMap<String, serde_json::Value>;

/// Computes the SAID of `sad` serialized as `format` and puts it into each
/// field named in `labels`: usually `d`, or `d` and `i` when an identifier
/// is its own SAID. While the digest is computed, those fields hold `#`
/// placeholders of the SAID's length. If `sad` has a version string in
/// `v`, its kind is set to `format` and its size to the length of the
/// serialization. Returns the SAID and the serialized SAD.
pub fn saidify(
    sad: &mut Sad,
    code: HashFunctionCode,
    format: SerializationFormats,
    labels: &[&str],
) -> Result<(SelfAddressingIdentifier, Vec<u8>), Error> {
    if labels.is_empty() {
        return Err(Error::MissingField("no SAID field given".into()));
    }
    let placeholder = serde_json::Value::String("#".repeat(code.full_size()));
    for label in labels {
        let field = sad
            .get_mut(*label)
            .ok_or_else(|| Error::MissingField((*label).into()))?;
        *field = placeholder.clone();
    }

    if let Some(version) = sad.get("v") {
        let mut info: SerializationInfo = version
            .as_str()
            .ok_or_else(|| Error::DeserializeError("v is not a version string".into()))?
            .parse()?;
        // the size field has a fixed width, so the length is the same after
        // it is filled in
        info.kind = format;
        info.size = 0;
        sad.insert("v".into(), info.to_str().into());
        info.size = format.encode(sad)?.len();
        sad.insert("v".into(), info.to_str().into());
    }

    let said = HashFunction::from(code).derive(&format.encode(sad)?);
    for label in labels {
        sad.insert((*label).into(), said.to_string().into());
    }
    let serialized = format.encode(sad)?;
    Ok((said, serialized))
}

/// Computes the SAID of a JSON map and puts it into `field_name`, `d` by
/// default. Fails if the field is missing.
pub fn make_me_happy(
    input: &str,
    derivation: HashFunctionCode,
    field_name: Option<&str>,
) -> Result<String, Error> {
    let mut sad: Sad =
        serde_json::from_str(input).map_err(|e| Error::DeserializeError(e.to_string()))?;
    let (_, out) = saidify(
        &mut sad,
        derivation,
        SerializationFormats::JSON,
        &[field_name.unwrap_or("d")],
    )?;
    String::from_utf8(out).map_err(|e| Error::SerializationError(e.to_string()))
}

/// Puts a version string for `version_str` as the first field `v` of a
/// JSON map, replacing any `v` it has, then computes its SAID into
/// `field_name`, `d` by default.
pub fn make_me_sad(
    input: &str,
    derivation: HashFunctionCode,
    version_str: ProtocolVersion,
    field_name: Option<&str>,
) -> Result<String, Error> {
    let mut data: Sad =
        serde_json::from_str(input).map_err(|e| Error::DeserializeError(e.to_string()))?;
    data.shift_remove("v");
    let version = SerializationInfo::new(
        version_str.prefix.to_string(),
        version_str.major,
        version_str.minor,
        sad::SerializationFormats::JSON,
        0,
    );
    let mut sad: Sad = [("v".to_string(), version.to_str().into())]
        .into_iter()
        .collect();
    sad.extend(data);
    let (_, out) = saidify(
        &mut sad,
        derivation,
        SerializationFormats::JSON,
        &[field_name.unwrap_or("d")],
    )?;
    String::from_utf8(out).map_err(|e| Error::SerializationError(e.to_string()))
}

#[test]
fn test_add_version() {
    let input_str = r#"{"v":"","hi":"there","d":"","blah":"blah"}"#;
    let protocol_version = ProtocolVersion::new("DKMS", 0, 0).unwrap();
    let json_with_version = make_me_sad(
        input_str,
        HashFunctionCode::Blake3_256,
        protocol_version,
        None,
    )
    .unwrap();
    assert_eq!(
        json_with_version,
        r#"{"v":"DKMS00JSON000067_","hi":"there","d":"EEjVw3gkdhqfHoLypHgpKtxWvK9II8B91g6EAP5Scdtb","blah":"blah"}"#
    );

    let mut map: IndexMap<String, String> = serde_json::from_str(&json_with_version).unwrap();
    // Check size
    let version: SerializationInfo = map.get("v").unwrap().parse().unwrap();
    assert_eq!(version.size, json_with_version.len());

    // Check digest
    let digest: SelfAddressingIdentifier = map.get("d").unwrap().parse().unwrap();
    let placeholder = "#".repeat(HashFunctionCode::Blake3_256.full_size());
    map.insert("d".to_string(), placeholder);
    let der_data = serde_json::to_vec(&map).unwrap();
    assert!(digest.verify_binding(&der_data));
}
