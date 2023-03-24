use std::str::FromStr;

use crate::error::Error;

use super::SelfAddressingPrefix;
mod digest;
use cesrox::primitives::codes::self_addressing::SelfAddressing;

/// Self Addressing Derivations
///
/// Wrapper over self addressing derivation codes supported by cesrox.
#[derive(Debug, PartialEq, Clone, Hash, Eq)]
pub struct SelfAddressingCode(pub(crate) SelfAddressing);

impl SelfAddressingCode {
    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        match &self.0 {
            SelfAddressing::Blake3_256 => digest::blake3_256_digest(data),
            SelfAddressing::Blake2B256(key) => digest::blake2b_256_digest(data, &key),
            SelfAddressing::Blake2S256(key) => digest::blake2s_256_digest(data, &key),
            SelfAddressing::SHA3_256 => digest::sha3_256_digest(data),
            SelfAddressing::SHA2_256 => digest::sha2_256_digest(data),
            SelfAddressing::Blake3_512 => digest::blake3_512_digest(data),
            SelfAddressing::SHA3_512 => digest::sha3_512_digest(data),
            SelfAddressing::Blake2B512 => digest::blake2b_512_digest(data),
            SelfAddressing::SHA2_512 => digest::sha2_512_digest(data),
        }
    }

    pub fn derive(&self, data: &[u8]) -> SelfAddressingPrefix {
        SelfAddressingPrefix::new(self.to_owned(), self.digest(data))
    }
}

impl From<&SelfAddressingCode> for SelfAddressing {
    fn from(val: &SelfAddressingCode) -> Self {
       val.0.clone()
    }
}

impl From<SelfAddressing> for SelfAddressingCode {
    fn from(csa: SelfAddressing) -> Self {
        SelfAddressingCode(csa)
    }
}

impl FromStr for SelfAddressingCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(SelfAddressingCode(s.parse()?))
    }
}

impl Default for SelfAddressingCode {
    fn default() -> Self {
        Self(SelfAddressing::Blake3_256)
    }
}
