use std::str::FromStr;

use crate::{derivation_code::DerivationCode, error::Error};

use self::{
    attached_signature_code::AttachedSignatureCode, basic::Basic, seed::SeedCode,
    self_addressing::SelfAddressing, self_signing::SelfSigning, rand_128::Rand128,
    timestamp::TimestampCode,
};

pub mod attached_signature_code;
pub mod basic;
pub mod seed;
pub mod self_addressing;
pub mod self_signing;
pub mod rand_128;
pub mod timestamp;

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum PrimitiveCode {
    Seed(SeedCode),
    Basic(Basic),
    SelfAddressing(SelfAddressing),
    SelfSigning(SelfSigning),
    SerialNumber(Rand128),
    Random(Rand128),
    IndexedSignature(AttachedSignatureCode),
    Timestamp(TimestampCode),
    Tag(TagCode),
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum TagCode {
    // 3 B64 encoded chars for special values
    Tag3([char; 3]),
    // 7 B64 encoded chars for special values
    Tag7([char; 7]),
}

impl DerivationCode for TagCode {
    fn hard_size(&self) -> usize {
        1
    }

    fn soft_size(&self) -> usize {
        match self {
            TagCode::Tag3(_) => 3,
            TagCode::Tag7(_) => 7,
        }
    }

    fn value_size(&self) -> usize {
        0
    }

    fn to_str(&self) -> String {
        match self {
            TagCode::Tag3(chars) => format!("X{}", chars.iter().collect::<String>()),
            TagCode::Tag7(chars) => format!("Y{}", chars.iter().collect::<String>()),
        }
    }
}

fn str_to_char_array<const N: usize>(s: &str) -> Option<[char; N]> {
    let chars: Vec<char> = s.chars().collect();
    chars.try_into().ok()
}

impl FromStr for TagCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[..1] {
            "X" => {
                let chars = &s[1..4];
                Ok(TagCode::Tag3(str_to_char_array(chars).unwrap()))
            }
            "Y" => {
                let chars = &s[1..8];
                Ok(TagCode::Tag7(str_to_char_array(chars).unwrap()))
            }
            _ => Err(Error::UnknownCodeError),
        }
    }
}

impl PrimitiveCode {
    pub fn to_str(&self) -> String {
        match self {
            PrimitiveCode::Seed(code) => code.to_str(),
            PrimitiveCode::Basic(code) => code.to_str(),
            PrimitiveCode::SelfAddressing(code) => code.to_str(),
            PrimitiveCode::SelfSigning(code) => code.to_str(),
            PrimitiveCode::SerialNumber(code) | PrimitiveCode::Random(code) => code.to_str(),
            PrimitiveCode::IndexedSignature(code) => code.to_str(),
            PrimitiveCode::Timestamp(code) => code.to_str(),
            PrimitiveCode::Tag(code) => code.to_str(),
        }
    }
}

impl FromStr for PrimitiveCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match SeedCode::from_str(s) {
            Ok(seed) => Ok(PrimitiveCode::Seed(seed)),
            Err(_) => match AttachedSignatureCode::from_str(s) {
                Ok(sig) => Ok(PrimitiveCode::IndexedSignature(sig)),
                Err(_) => match Basic::from_str(s) {
                    Ok(bp) => Ok(PrimitiveCode::Basic(bp)),
                    Err(_) => match SelfAddressing::from_str(s) {
                        Ok(sa) => Ok(PrimitiveCode::SelfAddressing(sa)),
                        Err(_) => match SelfSigning::from_str(s) {
                            Ok(ss) => Ok(PrimitiveCode::SelfSigning(ss)),
                            Err(_) => match Rand128::from_str(s) {
                                Ok(sn) => Ok(PrimitiveCode::SerialNumber(sn)),
                                Err(_) => match SeedCode::from_str(s) {
                                    Ok(seed) => Ok(PrimitiveCode::Seed(seed)),
                                    Err(_) => match TimestampCode::from_str(s) {
                                        Ok(ts) => Ok(PrimitiveCode::Timestamp(ts)),
                                        Err(_) => match TagCode::from_str(s) {
                                            Ok(tag) => Ok(PrimitiveCode::Tag(tag)),
                                            Err(_) => Err(Error::UnknownCodeError),
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        }
    }
}

impl DerivationCode for PrimitiveCode {
    fn hard_size(&self) -> usize {
        match self {
            PrimitiveCode::Seed(s) => s.hard_size(),
            PrimitiveCode::Basic(b) => b.hard_size(),
            PrimitiveCode::SelfAddressing(sa) => sa.hard_size(),
            PrimitiveCode::SelfSigning(ss) => ss.hard_size(),
            PrimitiveCode::SerialNumber(code) | PrimitiveCode::Random(code) => code.hard_size(),
            PrimitiveCode::IndexedSignature(i) => i.hard_size(),
            PrimitiveCode::Timestamp(code) => code.hard_size(),
            PrimitiveCode::Tag(tag_code) => tag_code.hard_size(),
        }
    }

    fn soft_size(&self) -> usize {
        match self {
            PrimitiveCode::Seed(s) => s.soft_size(),
            PrimitiveCode::Basic(b) => b.soft_size(),
            PrimitiveCode::SelfAddressing(sa) => sa.soft_size(),
            PrimitiveCode::SelfSigning(ss) => ss.soft_size(),
            PrimitiveCode::SerialNumber(code) | PrimitiveCode::Random(code) => code.soft_size(),
            PrimitiveCode::IndexedSignature(i) => i.soft_size(),
            PrimitiveCode::Timestamp(code) => code.soft_size(),
            PrimitiveCode::Tag(tag_code) => tag_code.soft_size(),
        }
    }

    fn value_size(&self) -> usize {
        match self {
            PrimitiveCode::Seed(s) => s.value_size(),
            PrimitiveCode::Basic(b) => b.value_size(),
            PrimitiveCode::SelfAddressing(sa) => sa.value_size(),
            PrimitiveCode::SelfSigning(ss) => ss.value_size(),
            PrimitiveCode::SerialNumber(code) | PrimitiveCode::Random(code) => code.value_size(),
            PrimitiveCode::IndexedSignature(i) => i.value_size(),
            PrimitiveCode::Timestamp(code) => code.value_size(),
            PrimitiveCode::Tag(tag_code) => tag_code.value_size(),
        }
    }

    fn to_str(&self) -> String {
        match self {
            PrimitiveCode::Seed(s) => s.to_str(),
            PrimitiveCode::Basic(b) => b.to_str(),
            PrimitiveCode::SelfAddressing(sa) => sa.to_str(),
            PrimitiveCode::SelfSigning(ss) => ss.to_str(),
            PrimitiveCode::SerialNumber(code) | PrimitiveCode::Random(code) => code.to_str(),
            PrimitiveCode::IndexedSignature(i) => i.to_str(),
            PrimitiveCode::Timestamp(code) => code.to_str(),
            PrimitiveCode::Tag(tag_code) => tag_code.to_str(),
        }
    }
}
