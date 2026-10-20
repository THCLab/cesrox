use std::io::Read;
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
    /// The digest of everything `reader` yields, read in chunks.
    pub fn digest_from_stream<R: Read>(&self, mut reader: R) -> Result<Vec<u8>, std::io::Error> {
        digest::digest_stream(&self.0, &mut reader)
    }

    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        digest::digest(&self.0, data)
    }

    pub fn derive(&self, data: &[u8]) -> SelfAddressingIdentifier {
        SelfAddressingIdentifier::new(self.to_owned(), self.digest(data))
    }
    /// The SAID of everything `reader` yields, read in chunks.
    pub fn derive_from_stream<R: Read>(
        &self,
        reader: R,
    ) -> Result<SelfAddressingIdentifier, std::io::Error> {
        let digest = self.digest_from_stream(reader)?;
        Ok(SelfAddressingIdentifier::new(self.to_owned(), digest))
    }
}

impl From<HashFunction> for HashFunctionCode {
    fn from(val: HashFunction) -> Self {
        val.0
    }
}

impl From<&HashFunction> for HashFunctionCode {
    fn from(val: &HashFunction) -> Self {
        val.to_owned().into()
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

#[test]
fn streaming_matches_one_shot_for_every_code() {
    use cesrox::primitives::codes::self_addressing::SelfAddressing;
    // larger than the read buffer, and not a multiple of it
    let data: Vec<u8> = (0..200_003u32).map(|i| (i % 251) as u8).collect();
    for code in [
        SelfAddressing::Blake3_256,
        SelfAddressing::Blake3_512,
        SelfAddressing::Blake2B256,
        SelfAddressing::Blake2B512,
        SelfAddressing::Blake2S256,
        SelfAddressing::SHA3_256,
        SelfAddressing::SHA3_512,
        SelfAddressing::SHA2_256,
        SelfAddressing::SHA2_512,
    ] {
        let hash = HashFunction::from(code.clone());
        assert_eq!(
            hash.digest_from_stream(&data[..]).unwrap(),
            hash.digest(&data),
            "{code:?}"
        );
    }
}
