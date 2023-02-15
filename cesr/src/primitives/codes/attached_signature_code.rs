use crate::{
    conversion::{adjust_with_num, b64_to_num},
    derivation_code::DerivationCode,
    error::Error,
    primitives::codes::self_signing::SelfSigning,
};
use core::str::FromStr;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Index {
    BothSame(u16),
    Dual(u16, u16),
    BigDual(u16, u16),
    CurrentOnly(u16),
    BigCurrentOnly(u16),
}
impl Index {
    pub fn current(&self) -> u16 {
        match self {
            Index::BothSame(i)
            | Index::Dual(i, _)
            | Index::BigDual(i, _)
            | Index::CurrentOnly(i)
            | Index::BigCurrentOnly(i) => *i,
        }
    }
    pub fn prev_next(&self) -> Option<u16> {
        match self {
            Index::BothSame(i) | Index::Dual(_, i) | Index::BigDual(_, i) => Some(*i),
            _ => None,
        }
    }
}
/// Attached Signature Derivation Codes
///
/// A self signing prefix derivation outputs a signature as its derivative (2.3.5)
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct AttachedSignatureCode {
    pub index: Index,
    pub code: SelfSigning,
}

impl AttachedSignatureCode {
    pub fn new(code: SelfSigning, index: Index) -> Self {
        Self { index, code }
    }

    pub fn new_from_ints(code: SelfSigning, current: u16, prev_next: Option<u16>) -> Self {
        let index = match prev_next {
            Some(i) => {
                if i == current {
                    Index::BothSame(i)
                } else {
                    Index::BigDual(current, i)
                }
            }
            None => Index::CurrentOnly(current),
        };
        Self { code, index }
    }
}

impl DerivationCode for AttachedSignatureCode {
    fn soft_size(&self) -> usize {
        match (self.code, self.index) {
            (SelfSigning::Ed25519Sha512, Index::BothSame(_)) => 1,
            (SelfSigning::Ed25519Sha512, Index::Dual(_, _)) => todo!(),
            (SelfSigning::Ed25519Sha512, Index::BigDual(_, _)) => 4,
            (SelfSigning::Ed25519Sha512, Index::CurrentOnly(_)) => 1,
            (SelfSigning::Ed25519Sha512, Index::BigCurrentOnly(_)) => 4,
            (SelfSigning::ECDSAsecp256k1Sha256, Index::BothSame(_)) => 1,
            (SelfSigning::ECDSAsecp256k1Sha256, Index::Dual(_, _)) => todo!(),
            (SelfSigning::ECDSAsecp256k1Sha256, Index::BigDual(_, _)) => 4,
            (SelfSigning::ECDSAsecp256k1Sha256, Index::CurrentOnly(_)) => 1,
            (SelfSigning::ECDSAsecp256k1Sha256, Index::BigCurrentOnly(_)) => 4,
            (SelfSigning::Ed448, Index::BothSame(_)) => todo!(),
            (SelfSigning::Ed448, Index::Dual(_, _)) => 2,
            (SelfSigning::Ed448, Index::BigDual(_, _)) => 6,
            (SelfSigning::Ed448, Index::CurrentOnly(_)) => 2,
            (SelfSigning::Ed448, Index::BigCurrentOnly(_)) => 6,
        }
    }

    fn hard_size(&self) -> usize {
        match (self.code, self.index) {
            (SelfSigning::Ed25519Sha512, Index::BothSame(_)) => 1,
            (SelfSigning::Ed25519Sha512, Index::Dual(_, _)) => todo!(),
            (SelfSigning::Ed25519Sha512, Index::BigDual(_, _)) => 2,
            (SelfSigning::Ed25519Sha512, Index::CurrentOnly(_)) => 1,
            (SelfSigning::Ed25519Sha512, Index::BigCurrentOnly(_)) => 2,
            (SelfSigning::ECDSAsecp256k1Sha256, Index::BothSame(_)) => 1,
            (SelfSigning::ECDSAsecp256k1Sha256, Index::Dual(_, _)) => todo!(),
            (SelfSigning::ECDSAsecp256k1Sha256, Index::BigDual(_, _)) => 2,
            (SelfSigning::ECDSAsecp256k1Sha256, Index::CurrentOnly(_)) => 1,
            (SelfSigning::ECDSAsecp256k1Sha256, Index::BigCurrentOnly(_)) => 2,
            (SelfSigning::Ed448, Index::BothSame(_)) => todo!(),
            (SelfSigning::Ed448, Index::Dual(_, _)) => 2,
            (SelfSigning::Ed448, Index::BigDual(_, _)) => 2,
            (SelfSigning::Ed448, Index::CurrentOnly(_)) => 2,
            (SelfSigning::Ed448, Index::BigCurrentOnly(_)) => 2,
        }
    }

    fn value_size(&self) -> usize {
        match (self.code, self.index) {
            (SelfSigning::Ed25519Sha512, _) => 86,
            (SelfSigning::ECDSAsecp256k1Sha256, _) => 86,
            (SelfSigning::Ed448, _) => 152,
        }
    }

    fn to_str(&self) -> String {
        let current = self.index.current();
        let prev_next = self.index.prev_next();
        let indexes_str = if let Some(i) = prev_next {
            [
                adjust_with_num(current, self.soft_size() / 2),
                adjust_with_num(i, self.soft_size() / 2),
            ]
            .join("")
        } else {
            adjust_with_num(current, self.soft_size())
        };
        [self.code.to_str(), indexes_str].join("")
    }
}

impl FromStr for AttachedSignatureCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[..1] {
            "A" => Ok(Self::new(
                SelfSigning::Ed25519Sha512,
                Index::BothSame(b64_to_num(&s.as_bytes()[1..2])?),
            )),
            "B" => Ok(Self::new(
                SelfSigning::Ed25519Sha512,
                Index::CurrentOnly(b64_to_num(&s.as_bytes()[1..2])?),
            )),
            "C" => Ok(Self::new(
                SelfSigning::ECDSAsecp256k1Sha256,
                Index::BothSame(b64_to_num(&s.as_bytes()[1..2])?),
            )),
            "D" => Ok(Self::new(
                SelfSigning::ECDSAsecp256k1Sha256,
                Index::CurrentOnly(b64_to_num(&s.as_bytes()[1..2])?),
            )),
            "0" => match &s[1..2] {
                "A" => Ok(Self::new(
                    SelfSigning::Ed448,
                    Index::BothSame(b64_to_num(&s.as_bytes()[2..3])?),
                )),
                "B" => Ok(Self::new(
                    SelfSigning::Ed448,
                    Index::CurrentOnly(b64_to_num(&s.as_bytes()[2..4])?),
                )),
                _ => Err(Error::UnknownCodeError),
            },
            "2" => match &s[1..2] {
                "A" => Ok(Self::new(
                    SelfSigning::Ed25519Sha512,
                    Index::BothSame(b64_to_num(&s.as_bytes()[2..4])?),
                )),
                "B" => Ok(Self::new(
                    SelfSigning::Ed25519Sha512,
                    Index::CurrentOnly(b64_to_num(&s.as_bytes()[2..6])?),
                )),
                "C" => Ok(Self::new(
                    SelfSigning::ECDSAsecp256k1Sha256,
                    Index::BothSame(b64_to_num(&s.as_bytes()[2..4])?),
                )),
                "D" => Ok(Self::new(
                    SelfSigning::ECDSAsecp256k1Sha256,
                    Index::CurrentOnly(b64_to_num(&s.as_bytes()[2..6])?),
                )),
                _ => Err(Error::UnknownCodeError),
            },
            "3" => match &s[1..2] {
                "A" => Ok(Self::new(
                    SelfSigning::Ed448,
                    Index::BothSame(b64_to_num(&s.as_bytes()[2..6])?),
                )),
                "B" => Ok(Self::new(
                    SelfSigning::Ed448,
                    Index::CurrentOnly(b64_to_num(&s.as_bytes()[2..10])?),
                )),
                _ => Err(Error::UnknownCodeError),
            },
            _ => Err(Error::UnknownCodeError),
        }
    }
}
