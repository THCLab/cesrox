#[cfg(feature = "file")]
use std::io::Read;

use blake2::{Blake2b, Digest, VarBlake2b, VarBlake2s};
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};

pub(crate) fn blake3_256_digest(input: &[u8]) -> Vec<u8> {
    blake3::hash(input).as_bytes().to_vec()
}

#[cfg(feature = "file")]
pub(crate) fn blake3_256_digest_stream<R: Read>(reader: &mut R) -> Result<Vec<u8>, std::io::Error> {
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 65536]; // 64 KB

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let hash = hasher.finalize();
    Ok(hash.as_bytes()[..32].to_vec()) // Truncate to 256 bits if needed
}

pub(crate) fn blake2s_256_digest(input: &[u8], key: &[u8]) -> Vec<u8> {
    use blake2::digest::{Update, VariableOutput};
    let mut hasher = VarBlake2s::new_keyed(key, 256);
    hasher.update(input);
    hasher.finalize_boxed().to_vec()
}

// TODO it seems that blake2b is always defined as outputting 512 bits?
// TODO updated -> is this the one?
pub(crate) fn blake2b_256_digest(input: &[u8], key: &[u8]) -> Vec<u8> {
    use blake2::digest::{Update, VariableOutput};
    let mut hasher = VarBlake2b::new_keyed(key, 256);
    hasher.update(input);
    hasher.finalize_boxed().to_vec()
}

pub(crate) fn blake3_512_digest(input: &[u8]) -> Vec<u8> {
    let mut out = [0u8; 64];
    let mut h = blake3::Hasher::new();
    h.update(input);
    h.finalize_xof().fill(&mut out);
    out.to_vec()
}

pub(crate) fn blake2b_512_digest(input: &[u8]) -> Vec<u8> {
    let mut hasher = Blake2b::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}

pub(crate) fn sha3_256_digest(input: &[u8]) -> Vec<u8> {
    let mut h = Sha3_256::new();
    h.update(input);
    h.finalize().to_vec()
}

pub(crate) fn sha2_256_digest(input: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(input);
    h.finalize().to_vec()
}

pub(crate) fn sha3_512_digest(input: &[u8]) -> Vec<u8> {
    let mut h = Sha3_512::new();
    h.update(input);
    h.finalize().to_vec()
}

pub(crate) fn sha2_512_digest(input: &[u8]) -> Vec<u8> {
    let mut h = Sha512::new();
    h.update(input);
    h.finalize().to_vec()
}
