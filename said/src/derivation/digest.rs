use std::io::Read;

use blake2::{Blake2b256, Blake2b512, Blake2s256, Digest};
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};

use super::HashFunctionCode;

/// An incremental hasher for any of the digest codes.
pub(crate) enum Hasher {
    Blake3_256(Box<blake3::Hasher>),
    Blake3_512(Box<blake3::Hasher>),
    Blake2b256(Blake2b256),
    Blake2b512(Blake2b512),
    Blake2s256(Blake2s256),
    Sha3_256(Sha3_256),
    Sha3_512(Sha3_512),
    Sha2_256(Sha256),
    Sha2_512(Sha512),
}

impl Hasher {
    pub(crate) fn new(code: &HashFunctionCode) -> Self {
        match code {
            HashFunctionCode::Blake3_256 => Hasher::Blake3_256(Box::default()),
            HashFunctionCode::Blake3_512 => Hasher::Blake3_512(Box::default()),
            HashFunctionCode::Blake2B256 => Hasher::Blake2b256(Blake2b256::new()),
            HashFunctionCode::Blake2B512 => Hasher::Blake2b512(Blake2b512::new()),
            HashFunctionCode::Blake2S256 => Hasher::Blake2s256(Blake2s256::new()),
            HashFunctionCode::SHA3_256 => Hasher::Sha3_256(Sha3_256::new()),
            HashFunctionCode::SHA3_512 => Hasher::Sha3_512(Sha3_512::new()),
            HashFunctionCode::SHA2_256 => Hasher::Sha2_256(Sha256::new()),
            HashFunctionCode::SHA2_512 => Hasher::Sha2_512(Sha512::new()),
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Blake3_256(h) | Hasher::Blake3_512(h) => {
                h.update(data);
            }
            Hasher::Blake2b256(h) => h.update(data),
            Hasher::Blake2b512(h) => h.update(data),
            Hasher::Blake2s256(h) => h.update(data),
            Hasher::Sha3_256(h) => h.update(data),
            Hasher::Sha3_512(h) => h.update(data),
            Hasher::Sha2_256(h) => h.update(data),
            Hasher::Sha2_512(h) => h.update(data),
        }
    }

    pub(crate) fn finalize(self) -> Vec<u8> {
        match self {
            Hasher::Blake3_256(h) => h.finalize().as_bytes().to_vec(),
            Hasher::Blake3_512(h) => {
                // Blake3's extendable output, read to 512 bits
                let mut out = [0u8; 64];
                h.finalize_xof().fill(&mut out);
                out.to_vec()
            }
            Hasher::Blake2b256(h) => h.finalize().to_vec(),
            Hasher::Blake2b512(h) => h.finalize().to_vec(),
            Hasher::Blake2s256(h) => h.finalize().to_vec(),
            Hasher::Sha3_256(h) => h.finalize().to_vec(),
            Hasher::Sha3_512(h) => h.finalize().to_vec(),
            Hasher::Sha2_256(h) => h.finalize().to_vec(),
            Hasher::Sha2_512(h) => h.finalize().to_vec(),
        }
    }
}

pub(crate) fn digest(code: &HashFunctionCode, data: &[u8]) -> Vec<u8> {
    let mut hasher = Hasher::new(code);
    hasher.update(data);
    hasher.finalize()
}

pub(crate) fn digest_stream<R: Read>(
    code: &HashFunctionCode,
    reader: &mut R,
) -> Result<Vec<u8>, std::io::Error> {
    let mut hasher = Hasher::new(code);
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(hasher.finalize());
        }
        hasher.update(&buffer[..read]);
    }
}
