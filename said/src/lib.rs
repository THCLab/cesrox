pub mod cesr_adapter;
pub mod derivation;
pub mod error;

use core::{fmt, str::FromStr};

use cesrox::primitives::CesrPrimitive;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use self::derivation::HashFunction;

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
