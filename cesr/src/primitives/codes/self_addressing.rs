//! Self-addressing codes: digests, used for self-addressing identifiers
//! and SAIDs.

use std::str::FromStr;

use crate::{derivation_code::DerivationCode, error::Error};

/// Code of a digest.
#[derive(Debug, PartialEq, Clone, Hash, Eq)]
pub enum SelfAddressing {
    /// `E`: Blake3-256 digest.
    Blake3_256,
    /// `F`: Blake2b-256 digest.
    Blake2B256,
    /// `G`: Blake2s-256 digest.
    Blake2S256,
    /// `H`: SHA3-256 digest.
    SHA3_256,
    /// `I`: SHA2-256 digest.
    SHA2_256,
    /// `0D`: Blake3-512 digest.
    Blake3_512,
    /// `0F`: SHA3-512 digest.
    SHA3_512,
    /// `0E`: Blake2b-512 digest.
    Blake2B512,
    /// `0G`: SHA2-512 digest.
    SHA2_512,
}

impl DerivationCode for SelfAddressing {
    fn value_size(&self) -> usize {
        match self {
            Self::Blake3_256
            | Self::Blake2B256
            | Self::Blake2S256
            | Self::SHA3_256
            | Self::SHA2_256 => 43,
            Self::Blake3_512 | Self::SHA3_512 | Self::Blake2B512 | Self::SHA2_512 => 86,
        }
    }

    fn soft_size(&self) -> usize {
        0
    }

    fn hard_size(&self) -> usize {
        match self {
            Self::Blake3_256
            | Self::Blake2B256
            | Self::Blake2S256
            | Self::SHA3_256
            | Self::SHA2_256 => 1,
            Self::Blake3_512 | Self::SHA3_512 | Self::Blake2B512 | Self::SHA2_512 => 2,
        }
    }

    fn to_str(&self) -> String {
        match self {
            Self::Blake3_256 => "E",
            Self::Blake2B256 => "F",
            Self::Blake2S256 => "G",
            Self::SHA3_256 => "H",
            Self::SHA2_256 => "I",
            Self::Blake3_512 => "0D",
            Self::Blake2B512 => "0E",
            Self::SHA3_512 => "0F",
            Self::SHA2_512 => "0G",
        }
        .into()
    }
}

impl FromStr for SelfAddressing {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.get(..1).ok_or(Error::Truncated)? {
            "E" => Ok(Self::Blake3_256),
            "F" => Ok(Self::Blake2B256),
            "G" => Ok(Self::Blake2S256),
            "H" => Ok(Self::SHA3_256),
            "I" => Ok(Self::SHA2_256),
            "0" => match s.get(1..2).ok_or(Error::Truncated)? {
                "D" => Ok(Self::Blake3_512),
                "E" => Ok(Self::Blake2B512),
                "F" => Ok(Self::SHA3_512),
                "G" => Ok(Self::SHA2_512),
                _ => Err(Error::UnknownCode),
            },
            _ => Err(Error::UnknownCode),
        }
    }
}

/// Placeholder of `#` characters as long as a digest of type `derivation`,
/// written into the digest field before the digest is computed.
pub fn dummy_prefix(derivation: &SelfAddressing) -> String {
    "#".repeat(derivation.code_size() + derivation.value_size())
}
