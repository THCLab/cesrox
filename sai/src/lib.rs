pub mod cesr_adapter;
pub mod derivation;
pub mod error;
pub mod sad;

use core::{fmt, str::FromStr};

use cesrox::primitives::CesrPrimitive;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use self::derivation::SelfAddressingCode;

/// Self Addressing Prefix
///
/// Self-addressing is a digest/hash of data. 
#[derive(PartialEq, Clone, Hash, Eq, Default)]
pub struct SelfAddressingPrefix {
    pub derivation: SelfAddressingCode,
    pub digest: Vec<u8>,
}

impl fmt::Debug for SelfAddressingPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.to_str())
    }
}

impl SelfAddressingPrefix {
    pub fn new(code: SelfAddressingCode, digest: Vec<u8>) -> Self {
        Self {
            derivation: code,
            digest,
        }
    }

    pub fn verify_binding(&self, sed: &[u8]) -> bool {
        self.derivation.digest(sed) == self.digest
    }
}

impl fmt::Display for SelfAddressingPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

/// Serde compatible Serialize
impl Serialize for SelfAddressingPrefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str())
    }
}

/// Serde compatible Deserialize
impl<'de> Deserialize<'de> for SelfAddressingPrefix {
    fn deserialize<D>(deserializer: D) -> Result<SelfAddressingPrefix, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        SelfAddressingPrefix::from_str(&s).map_err(serde::de::Error::custom)
    }
}