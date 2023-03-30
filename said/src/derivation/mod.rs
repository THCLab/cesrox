use std::str::FromStr;

use crate::error::Error;

use super::SelfAddressingIdentifier;
mod digest;
pub use cesrox::primitives::codes::self_addressing::SelfAddressing as HashFunctionCode;

/// Hash Function
///
/// Wrapper over possible hash function codes supported by cesrox
/// (SelfAddressing derivation). Provides a way of computing digest depending on
/// specified algorithm code.
#[derive(Debug, PartialEq, Clone, Hash, Eq)]
pub struct HashFunction(pub(crate) HashFunctionCode);

impl HashFunction {
    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        match &self.0 {
            HashFunctionCode::Blake3_256 => digest::blake3_256_digest(data),
            HashFunctionCode::Blake2B256(key) => digest::blake2b_256_digest(data, key),
            HashFunctionCode::Blake2S256(key) => digest::blake2s_256_digest(data, key),
            HashFunctionCode::SHA3_256 => digest::sha3_256_digest(data),
            HashFunctionCode::SHA2_256 => digest::sha2_256_digest(data),
            HashFunctionCode::Blake3_512 => digest::blake3_512_digest(data),
            HashFunctionCode::SHA3_512 => digest::sha3_512_digest(data),
            HashFunctionCode::Blake2B512 => digest::blake2b_512_digest(data),
            HashFunctionCode::SHA2_512 => digest::sha2_512_digest(data),
        }
    }

    pub fn derive(&self, data: &[u8]) -> SelfAddressingIdentifier {
        SelfAddressingIdentifier::new(self.to_owned(), self.digest(data))
    }
}

impl From<&HashFunction> for HashFunctionCode {
    fn from(val: &HashFunction) -> Self {
        val.0.clone()
    }
}

impl From<HashFunctionCode> for HashFunction {
    fn from(csa: HashFunctionCode) -> Self {
        HashFunction(csa)
    }
}

impl FromStr for HashFunction {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(HashFunction(s.parse()?))
    }
}

impl Default for HashFunction {
    fn default() -> Self {
        Self(HashFunctionCode::Blake3_256)
    }
}
