//! Seed codes: random seeds from which private keys are derived.

use std::str::FromStr;

use crate::{derivation_code::DerivationCode, error::Error};

/// Code of a private key seed.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum SeedCode {
    /// `A`: 256-bit random seed of an Ed25519 private key.
    RandomSeed256Ed25519,
    /// `J`: 256-bit random seed of an ECDSA secp256k1 private key.
    RandomSeed256ECDSAsecp256k1,
    /// `K`: 456-bit random seed of an Ed448 private key.
    RandomSeed448,
    /// `Q`: 256-bit random seed of an ECDSA secp256r1 (P-256) private key.
    RandomSeed256ECDSA256r1,
}

impl DerivationCode for SeedCode {
    fn value_size(&self) -> usize {
        match self {
            SeedCode::RandomSeed256Ed25519 => 43,
            SeedCode::RandomSeed256ECDSAsecp256k1 => 43,
            SeedCode::RandomSeed448 => 75,
            SeedCode::RandomSeed256ECDSA256r1 => 43,
        }
    }

    fn soft_size(&self) -> usize {
        0
    }

    fn hard_size(&self) -> usize {
        match self {
            SeedCode::RandomSeed256Ed25519 => 1,
            SeedCode::RandomSeed256ECDSAsecp256k1 => 1,
            SeedCode::RandomSeed448 => 1,
            SeedCode::RandomSeed256ECDSA256r1 => 1,
        }
    }

    fn to_str(&self) -> String {
        match self {
            Self::RandomSeed256Ed25519 => "A".to_string(),
            Self::RandomSeed256ECDSAsecp256k1 => "J".to_string(),
            Self::RandomSeed448 => "K".to_string(),
            Self::RandomSeed256ECDSA256r1 => "Q".to_string(),
        }
    }
}

impl FromStr for SeedCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.get(..1).ok_or(Error::Truncated)? {
            "A" => Ok(Self::RandomSeed256Ed25519),
            "J" => Ok(Self::RandomSeed256ECDSAsecp256k1),
            "K" => Ok(Self::RandomSeed448),
            "Q" => Ok(Self::RandomSeed256ECDSA256r1),
            _ => Err(Error::UnknownCode),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_256r1_seed_code_roundtrip() {
        let code = SeedCode::RandomSeed256ECDSA256r1;
        assert_eq!(code.to_str(), "Q");
        assert_eq!(SeedCode::from_str("Q").unwrap(), code);
        assert_eq!(code.value_size(), 43);
        assert_eq!(code.hard_size(), 1);
    }
}
