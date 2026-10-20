//! CESR primitives: a derivation code followed by the raw bytes it
//! describes, such as keys, digests and signatures.

pub mod codes;
pub(crate) mod parsers;

use chrono::{DateTime, FixedOffset};
pub use parsers::parse_primitive;

use crate::{conversion::from_bytes_to_text, primitives::codes::rand_128::Rand128Code};

use self::codes::{
    attached_signature_code::AttachedSignatureCode, basic::Basic, self_addressing::SelfAddressing,
    self_signing::SelfSigning, PrimitiveCode,
};

/// Code of an identifier prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentifierCode {
    /// Prefix that is a public key.
    Basic(Basic),
    /// Prefix that is a digest (self-addressing identifier).
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
    /// Derivation code of the primitive.
    pub code: C,
    /// Raw bytes, without the code.
    pub raw: Vec<u8>,
}

impl<C> Primitive<C> {
    /// Creates a primitive from its code and raw bytes.
    pub fn new(code: C, raw: Vec<u8>) -> Self {
        Primitive { code, raw }
    }
}

impl<C> From<(C, Vec<u8>)> for Primitive<C> {
    fn from((code, raw): (C, Vec<u8>)) -> Self {
        Primitive { code, raw }
    }
}

/// Identifier prefix: a public key or a digest.
pub type Identifier = Primitive<IdentifierCode>;
/// Public key.
pub type PublicKey = Primitive<Basic>;
/// Digest.
pub type Digest = Primitive<SelfAddressing>;
/// Signature without an index.
pub type Signature = Primitive<SelfSigning>;
/// Signature with the index of the signing key in the key list.
pub type IndexedSignature = Primitive<AttachedSignatureCode>;
/// 128-bit random value (`0A`).
pub type Nonce = Primitive<Rand128Code>;
/// Date and time with a UTC offset, as carried by the `1AAG` code.
pub type Timestamp = DateTime<FixedOffset>;

/// Seal pointing at an event in another identifier's log: its prefix,
/// sequence number and digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchoringEventSeal {
    /// Identifier whose log holds the event.
    pub prefix: Identifier,
    /// Sequence number of the event.
    pub sn: u128,
    /// Digest of the event.
    pub digest: Digest,
}

/// A value that can be written as a CESR primitive in the text domain.
pub trait CesrPrimitive {
    /// Raw bytes of the primitive, without the code.
    fn derivative(&self) -> Vec<u8>;
    /// Derivation code of the primitive.
    fn derivation_code(&self) -> PrimitiveCode;
    /// Text of the primitive: the code followed by the Base64 raw bytes.
    /// Empty when there are no raw bytes.
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
