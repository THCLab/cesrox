pub mod codes;
pub(crate) mod parsers;

use chrono::{DateTime, FixedOffset};
pub use parsers::parse_primitive;

use crate::{conversion::from_bytes_to_text, primitives::codes::rand_128::Rand128Code};

use self::codes::{
    attached_signature_code::AttachedSignatureCode, basic::Basic, self_addressing::SelfAddressing,
    self_signing::SelfSigning, PrimitiveCode,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentifierCode {
    Basic(Basic),
    SelfAddressing(SelfAddressing),
}

impl From<IdentifierCode> for PrimitiveCode {
    fn from(code: IdentifierCode) -> Self {
        match code {
            IdentifierCode::Basic(b) => PrimitiveCode::Basic(b),
            IdentifierCode::SelfAddressing(sa) => PrimitiveCode::SelfAddressing(sa),
        }
    }
}

impl From<Basic> for PrimitiveCode {
    fn from(code: Basic) -> Self {
        PrimitiveCode::Basic(code)
    }
}

impl From<SelfAddressing> for PrimitiveCode {
    fn from(code: SelfAddressing) -> Self {
        PrimitiveCode::SelfAddressing(code)
    }
}

impl From<SelfSigning> for PrimitiveCode {
    fn from(code: SelfSigning) -> Self {
        PrimitiveCode::SelfSigning(code)
    }
}

impl From<AttachedSignatureCode> for PrimitiveCode {
    fn from(code: AttachedSignatureCode) -> Self {
        PrimitiveCode::IndexedSignature(code)
    }
}

impl From<Rand128Code> for PrimitiveCode {
    fn from(code: Rand128Code) -> Self {
        PrimitiveCode::Random(code)
    }
}

/// A primitive: a code from the table `C` and the raw bytes it describes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Primitive<C> {
    pub code: C,
    pub raw: Vec<u8>,
}

impl<C> Primitive<C> {
    pub fn new(code: C, raw: Vec<u8>) -> Self {
        Primitive { code, raw }
    }
}

impl<C> From<(C, Vec<u8>)> for Primitive<C> {
    fn from((code, raw): (C, Vec<u8>)) -> Self {
        Primitive { code, raw }
    }
}

pub type Identifier = Primitive<IdentifierCode>;
pub type PublicKey = Primitive<Basic>;
pub type Digest = Primitive<SelfAddressing>;
pub type Signature = Primitive<SelfSigning>;
pub type IndexedSignature = Primitive<AttachedSignatureCode>;
pub type Nonce = Primitive<Rand128Code>;
pub type Timestamp = DateTime<FixedOffset>;

/// Seal pointing at an event in another identifier's log: its prefix,
/// sequence number and digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchoringEventSeal {
    pub prefix: Identifier,
    pub sn: u64,
    pub digest: Digest,
}

pub trait CesrPrimitive {
    fn derivative(&self) -> Vec<u8>;
    fn derivation_code(&self) -> PrimitiveCode;
    fn to_str(&self) -> String {
        match self.derivative().len() {
            // empty data cannot be prefixed!
            0 => "".to_string(),
            _ => {
                let dc = self.derivation_code().to_str();
                let lead_bytes = if !dc.len().is_multiple_of(4) {
                    dc.len() % 4
                } else {
                    0
                };
                // replace lead bytes with code
                let derivative_text =
                    from_bytes_to_text(&self.derivative())[lead_bytes..].to_string();
                [dc, derivative_text].join("")
            }
        }
    }
}

impl<C: Clone + Into<PrimitiveCode>> CesrPrimitive for Primitive<C> {
    fn derivative(&self) -> Vec<u8> {
        self.raw.clone()
    }

    fn derivation_code(&self) -> PrimitiveCode {
        self.code.clone().into()
    }
}
