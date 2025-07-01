pub mod codes;
pub mod parsers;
use chrono::{DateTime, FixedOffset};

use crate::{conversion::from_bytes_to_text, primitives::codes::seed::SeedCode};

use self::codes::{
    attached_signature_code::AttachedSignatureCode, basic::Basic, self_addressing::SelfAddressing,
    self_signing::SelfSigning, PrimitiveCode,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentifierCode {
    Basic(Basic),
    SelfAddressing(SelfAddressing),
}

pub type Identifier = (IdentifierCode, Vec<u8>);
pub type PublicKey = (Basic, Vec<u8>);
pub type Digest = (SelfAddressing, Vec<u8>);
pub type Signature = (SelfSigning, Vec<u8>);
pub type IndexedSignature = (AttachedSignatureCode, Vec<u8>);
pub type Timestamp = DateTime<FixedOffset>;
pub type AnchoringEventSeal = (Identifier, u64, Digest);
pub type SaltyNounce = (SeedCode, Vec<u8>);

pub trait CesrPrimitive {
    fn derivative(&self) -> Vec<u8>;
    fn derivation_code(&self) -> PrimitiveCode;
    fn to_str(&self) -> String {
        match self.derivative().len() {
            // empty data cannot be prefixed!
            0 => "".to_string(),
            _ => {
                let dc = self.derivation_code().to_str();
                let lead_bytes = if dc.len() % 4 != 0 { dc.len() % 4 } else { 0 };
                // replace lead bytes with code
                let derivative_text =
                    from_bytes_to_text(&self.derivative())[lead_bytes..].to_string();
                [dc, derivative_text].join("")
            }
        }
    }
}

impl CesrPrimitive for Digest {
    fn derivative(&self) -> Vec<u8> {
        self.1.clone()
    }

    fn derivation_code(&self) -> PrimitiveCode {
        PrimitiveCode::SelfAddressing(self.0.clone())
    }
}

impl CesrPrimitive for Signature {
    fn derivative(&self) -> Vec<u8> {
        self.1.clone()
    }

    fn derivation_code(&self) -> PrimitiveCode {
        PrimitiveCode::SelfSigning(self.0)
    }
}

impl CesrPrimitive for IndexedSignature {
    fn derivative(&self) -> Vec<u8> {
        self.1.clone()
    }

    fn derivation_code(&self) -> PrimitiveCode {
        PrimitiveCode::IndexedSignature(self.0)
    }
}

impl CesrPrimitive for PublicKey {
    fn derivative(&self) -> Vec<u8> {
        self.1.clone()
    }

    fn derivation_code(&self) -> PrimitiveCode {
        PrimitiveCode::Basic(self.0)
    }
}

impl CesrPrimitive for Identifier {
    fn derivative(&self) -> Vec<u8> {
        self.1.clone()
    }

    fn derivation_code(&self) -> PrimitiveCode {
        match &self.0 {
            IdentifierCode::Basic(b) => PrimitiveCode::Basic(*b),
            IdentifierCode::SelfAddressing(sa) => PrimitiveCode::SelfAddressing(sa.clone()),
        }
    }
}

impl CesrPrimitive for SaltyNounce {
    fn derivative(&self) -> Vec<u8> {
        self.1.clone()
    }

    fn derivation_code(&self) -> PrimitiveCode {
        PrimitiveCode::Seed(self.0.clone())
    }
}
