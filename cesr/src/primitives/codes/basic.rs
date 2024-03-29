use std::str::FromStr;

use crate::{derivation_code::DerivationCode, error::Error};

#[derive(Debug, PartialEq, Clone, Copy, Hash, Eq)]
pub enum Basic {
    ECDSAsecp256k1Nontrans,
    ECDSAsecp256k1,
    Ed25519Nontrans,
    Ed25519,
    Ed448Nontrans,
    Ed448,
    X25519,
    X448,
}

impl DerivationCode for Basic {
    fn value_size(&self) -> usize {
        match self {
            Self::Ed25519Nontrans | Self::Ed25519 | Self::X25519 => 43,
            Self::X448 => 75,
            Self::ECDSAsecp256k1Nontrans | Self::ECDSAsecp256k1 => 44,
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
        }
        .into()
    }
}

impl FromStr for Basic {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.get(..1).ok_or(Error::EmptyCodeError)? {
            "B" => Ok(Self::Ed25519Nontrans),
            "C" => Ok(Self::X25519),
            "D" => Ok(Self::Ed25519),
            "L" => Ok(Self::X448),
            "1" => match &s[1..4] {
                "AAA" => Ok(Self::ECDSAsecp256k1Nontrans),
                "AAB" => Ok(Self::ECDSAsecp256k1),
                "AAC" => Ok(Self::Ed448Nontrans),
                "AAD" => Ok(Self::Ed448),
                _ => Err(Error::UnknownCodeError),
            },
            _ => Err(Error::UnknownCodeError),
        }
    }
}
