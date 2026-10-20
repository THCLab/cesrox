use std::str::FromStr;

use crate::{derivation_code::DerivationCode, error::Error};

use self::{
    attached_signature_code::AttachedSignatureCode,
    basic::Basic,
    material::{MaterialCode, SpecialCode},
    number::NumberCode,
    rand_128::Rand128Code,
    seed::SeedCode,
    self_addressing::SelfAddressing,
    self_signing::SelfSigning,
    timestamp::TimestampCode,
};

pub mod attached_signature_code;
pub mod basic;
pub mod material;
pub mod number;
pub mod rand_128;
pub mod seed;
pub mod self_addressing;
pub mod self_signing;
pub mod tag;
pub mod timestamp;

pub use tag::TagCode;

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
    Material(MaterialCode),
    Special(SpecialCode),
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
            PrimitiveCode::Material(code) => code,
            PrimitiveCode::Special(code) => code,
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
            |s| MaterialCode::from_str(s).map(Material),
            |s| SpecialCode::from_str(s).map(Special),
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

    fn lead_size(&self) -> usize {
        self.inner().lead_size()
    }
}
