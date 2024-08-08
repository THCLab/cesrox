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

#[derive(Serialize)]
struct Version<D> {
    v: SerializationInfo,
    #[serde(flatten)]
    data: D,
}

/// Adds version string as first field to provided json. Version is
/// provided as triplet: (version_string, major version, minor version). If json
/// contains `d` field it computes digest and place it in `d` field.
pub fn add_version_field(
    input: &str,
    derivation: HashFunctionCode,
    version_str: (&str, u8, u8),
) -> Result<String, Error> {
    let json: IndexMap<String, serde_json::Value> =
        serde_json::from_str(input).map_err(|e| Error::DeserializeError(e.to_string()))?;
    // Use default version string with size 0
    let version = SerializationInfo::new(
        version_str.0.to_string(),
        version_str.1,
        version_str.2,
        sad::SerializationFormats::JSON,
        0,
    );
    let mut versioned = Version {
        v: version,
        data: json,
    };

    // If there's a `d` field, replace it with placeholder string of proper length
    if let Some(digest_field) = versioned.data.get_mut("d") {
        let placeholder = "#".repeat(derivation.full_size());
        *digest_field = serde_json::Value::String(placeholder);
    }

    // Compute length and replace size in version string
    let derivation_data = SerializationFormats::JSON
        .encode(&versioned)
        .expect("Unexpected error: missing `v` field");
    let len = derivation_data.len();
    versioned.v.size = len;

    // Compute digest and replace placeholder string in `d` field
    let derivation_data = SerializationFormats::JSON
        .encode(&versioned)
        .expect("Unexpected error: missing `v` field");
    let out = if let Some(digest_field) = versioned.data.get_mut("d") {
        let said = HashFunction::from(derivation).derive(&derivation_data);
        *digest_field = serde_json::Value::String(said.to_string());
        SerializationFormats::JSON.encode(&versioned)?
    } else {
        derivation_data
    };

    String::from_utf8(out).map_err(|e| Error::SerializationError(e.to_string()))
}

#[test]
fn test_add_version() {
    let input_str = r#"{"hi":"there","d":"","blah":"blah"}"#;
    let json_with_version =
        add_version_field(&input_str, HashFunctionCode::Blake3_256, ("DKMS", 0, 0)).unwrap();

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
