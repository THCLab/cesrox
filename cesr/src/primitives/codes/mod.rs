//! Derivation code tables, one module per family of primitives.

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

/// Any primitive code, tagged with its family.
#[derive(PartialEq, Eq, Debug, Clone)]
#[non_exhaustive]
pub enum PrimitiveCode {
    /// Private key seed.
    Seed(SeedCode),
    /// Public key.
    Basic(Basic),
    /// Digest.
    SelfAddressing(SelfAddressing),
    /// Signature without an index.
    SelfSigning(SelfSigning),
    /// Sequence number written as a 128-bit salt, the form used before
    /// CESR V2.
    SerialNumber(Rand128Code),
    /// 128-bit random value.
    Random(Rand128Code),
    /// Signature with a key index.
    IndexedSignature(AttachedSignatureCode),
    /// Date-time.
    Timestamp(TimestampCode),
    /// Short Base64 tag.
    Tag(TagCode),
    /// Unsigned integer.
    Number(NumberCode),
    /// Cipher material, salt or label.
    Material(MaterialCode),
    /// Special value that carries no data.
    Special(SpecialCode),
}

impl PrimitiveCode {
    /// Text of the code.
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
