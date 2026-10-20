use std::str::FromStr;

use crate::{derivation_code::DerivationCode, error::Error};

use self::{
    attached_signature_code::AttachedSignatureCode, basic::Basic, number::NumberCode,
    rand_128::Rand128Code, seed::SeedCode, self_addressing::SelfAddressing,
    self_signing::SelfSigning, timestamp::TimestampCode,
};

pub mod attached_signature_code;
pub mod basic;
pub mod number;
pub mod rand_128;
pub mod seed;
pub mod self_addressing;
pub mod self_signing;
pub mod timestamp;

#[derive(PartialEq, Eq, Debug, Clone)]
#[non_exhaustive]
pub enum PrimitiveCode {
    Seed(SeedCode),
    Basic(Basic),
    SelfAddressing(SelfAddressing),
    SelfSigning(SelfSigning),
    SerialNumber(Rand128Code),
    Random(Rand128Code),
    IndexedSignature(AttachedSignatureCode),
    Timestamp(TimestampCode),
    Tag(TagCode),
    Number(NumberCode),
}

#[derive(PartialEq, Eq, Debug, Clone)]
#[non_exhaustive]
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
        match s.get(..1).ok_or(Error::Truncated)? {
            "X" => {
                let chars = s.get(1..4).ok_or(Error::Truncated)?;
                Ok(TagCode::Tag3(
                    str_to_char_array(chars).ok_or(Error::UnknownCode)?,
                ))
            }
            "Y" => {
                let chars = s.get(1..8).ok_or(Error::Truncated)?;
                Ok(TagCode::Tag7(
                    str_to_char_array(chars).ok_or(Error::UnknownCode)?,
                ))
            }
            _ => Err(Error::UnknownCode),
        }
    }
}

impl PrimitiveCode {
    pub fn to_str(&self) -> String {
        self.inner().to_str()
    }

    /// The code of the family this primitive belongs to.
    fn inner(&self) -> &dyn DerivationCode {
        match self {
            PrimitiveCode::Seed(code) => code,
            PrimitiveCode::Basic(code) => code,
            PrimitiveCode::SelfAddressing(code) => code,
            PrimitiveCode::SelfSigning(code) => code,
            PrimitiveCode::SerialNumber(code) | PrimitiveCode::Random(code) => code,
            PrimitiveCode::IndexedSignature(code) => code,
            PrimitiveCode::Timestamp(code) => code,
            PrimitiveCode::Tag(code) => code,
            PrimitiveCode::Number(code) => code,
        }
    }
}

impl FromStr for PrimitiveCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use PrimitiveCode::*;

        type ParserFn = fn(&str) -> Result<PrimitiveCode, Error>;

        // Indexed signature codes are a separate table, valid only inside
        // signature groups; read here they would shadow B, C and D keys.
        let parsers: &[ParserFn] = &[
            |s| Rand128Code::from_str(s).map(Random),
            |s| SeedCode::from_str(s).map(Seed),
            |s| basic::Basic::from_str(s).map(Basic),
            |s| self_addressing::SelfAddressing::from_str(s).map(SelfAddressing),
            |s| self_signing::SelfSigning::from_str(s).map(SelfSigning),
            |s| Rand128Code::from_str(s).map(SerialNumber),
            |s| SeedCode::from_str(s).map(Seed),
            |s| TimestampCode::from_str(s).map(Timestamp),
            |s| TagCode::from_str(s).map(Tag),
            |s| NumberCode::from_str(s).map(Number),
        ];

        for parser in parsers {
            if let Ok(code) = parser(s) {
                return Ok(code);
            }
        }

        Err(Error::UnknownCode)
    }
}

impl DerivationCode for PrimitiveCode {
    fn hard_size(&self) -> usize {
        self.inner().hard_size()
    }

    fn soft_size(&self) -> usize {
        self.inner().soft_size()
    }

    fn value_size(&self) -> usize {
        self.inner().value_size()
    }

    fn to_str(&self) -> String {
        self.inner().to_str()
    }
}
