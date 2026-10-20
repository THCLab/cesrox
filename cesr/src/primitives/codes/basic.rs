//! Basic codes: public keys used directly as identifier prefixes or as
//! keys in key lists.

use std::str::FromStr;

use crate::{derivation_code::DerivationCode, error::Error};

/// Code of a public key.
#[derive(Debug, PartialEq, Clone, Copy, Hash, Eq)]
#[non_exhaustive]
pub enum Basic {
    /// `1AAA`: ECDSA secp256k1 public key of a non-transferable identifier.
    ECDSAsecp256k1Nontrans,
    /// `1AAB`: ECDSA secp256k1 public key of a transferable identifier.
    ECDSAsecp256k1,
    /// `B`: Ed25519 public key of a non-transferable identifier.
    Ed25519Nontrans,
    /// `D`: Ed25519 public key of a transferable identifier.
    Ed25519,
    /// `1AAC`: Ed448 public key of a non-transferable identifier.
    Ed448Nontrans,
    /// `1AAD`: Ed448 public key of a transferable identifier.
    Ed448,
    /// `C`: X25519 public encryption key.
    X25519,
    /// `L`: X448 public encryption key.
    X448,
    /// `1AAI`: ECDSA secp256r1 (P-256) public key of a non-transferable
    /// identifier.
    ECDSA256r1Nontrans,
    /// `1AAJ`: ECDSA secp256r1 (P-256) public key of a transferable
    /// identifier.
    ECDSA256r1,
}

impl DerivationCode for Basic {
    fn value_size(&self) -> usize {
        match self {
            Self::Ed25519Nontrans | Self::Ed25519 | Self::X25519 => 43,
            Self::X448 => 75,
            Self::ECDSAsecp256k1Nontrans | Self::ECDSAsecp256k1 => 44,
            Self::ECDSA256r1Nontrans | Self::ECDSA256r1 => 44,
            Self::Ed448Nontrans | Self::Ed448 => 76,
        }
    }

    fn soft_size(&self) -> usize {
        0
    }

    fn hard_size(&self) -> usize {
        match self {
            Self::Ed25519Nontrans | Self::X25519 | Self::Ed25519 | Self::X448 => 1,
            Self::ECDSAsecp256k1Nontrans
            | Self::ECDSAsecp256k1
            | Self::ECDSA256r1Nontrans
            | Self::ECDSA256r1
            | Self::Ed448Nontrans
            | Self::Ed448 => 4,
        }
    }

    fn to_str(&self) -> String {
        match self {
            Self::Ed25519Nontrans => "B",
            Self::X25519 => "C",
            Self::Ed25519 => "D",
            Self::X448 => "L",
            Self::ECDSAsecp256k1Nontrans => "1AAA",
            Self::ECDSAsecp256k1 => "1AAB",
            Self::Ed448Nontrans => "1AAC",
            Self::Ed448 => "1AAD",
            Self::ECDSA256r1Nontrans => "1AAI",
            Self::ECDSA256r1 => "1AAJ",
        }
        .into()
    }
}

impl FromStr for Basic {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.get(..1).ok_or(Error::Truncated)? {
            "B" => Ok(Self::Ed25519Nontrans),
            "C" => Ok(Self::X25519),
            "D" => Ok(Self::Ed25519),
            "L" => Ok(Self::X448),
            "1" => match s.get(1..4).ok_or(Error::Truncated)? {
                "AAA" => Ok(Self::ECDSAsecp256k1Nontrans),
                "AAB" => Ok(Self::ECDSAsecp256k1),
                "AAC" => Ok(Self::Ed448Nontrans),
                "AAD" => Ok(Self::Ed448),
                "AAI" => Ok(Self::ECDSA256r1Nontrans),
                "AAJ" => Ok(Self::ECDSA256r1),
                _ => Err(Error::UnknownCode),
            },
            _ => Err(Error::UnknownCode),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_256r1_codes_roundtrip() {
        for code in [Basic::ECDSA256r1Nontrans, Basic::ECDSA256r1] {
            let s = code.to_str();
            assert_eq!(Basic::from_str(&s).unwrap(), code);
        }
        assert_eq!(Basic::ECDSA256r1Nontrans.to_str(), "1AAI");
        assert_eq!(Basic::ECDSA256r1.to_str(), "1AAJ");
        assert_eq!(Basic::ECDSA256r1.value_size(), 44);
        assert_eq!(Basic::ECDSA256r1.hard_size(), 4);
    }
}
