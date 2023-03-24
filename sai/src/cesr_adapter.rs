use std::str::FromStr;

use super::{SelfAddressingCode, SelfAddressingPrefix};

use cesrox::{
    conversion::from_text_to_bytes,
    derivation_code::DerivationCode,
    primitives::{
        codes::{self_addressing::SelfAddressing, PrimitiveCode},
        CesrPrimitive, Digest,
    },
};

impl SelfAddressingCode {
    pub fn get_len(&self) -> usize {
        let cesr_code: SelfAddressing = (self).into();
        cesr_code.full_size()
    }
}

impl CesrPrimitive for SelfAddressingPrefix {
    fn derivative(&self) -> Vec<u8> {
        self.digest.clone()
    }
    fn derivation_code(&self) -> PrimitiveCode {
        PrimitiveCode::SelfAddressing((&self.derivation).into())
    }
}

impl FromStr for SelfAddressingPrefix {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = SelfAddressing::from_str(s)?;
        let c_len = code.code_size();
        if s.len() == code.full_size() {
            let decoded = from_text_to_bytes(s[c_len..].as_bytes())?[c_len..].to_vec();

            Ok(Self::new(code.into(), decoded))
        } else {
            Err(Self::Err::IncorrectLengthError(s.into()))
        }
    }
}

impl From<Digest> for SelfAddressingPrefix {
    fn from((code, digest): Digest) -> Self {
        SelfAddressingPrefix::new(code.into(), digest)
    }
}

impl From<&SelfAddressingPrefix> for Digest {
    fn from(val: &SelfAddressingPrefix) -> Self {
        ((&val.derivation).into(), val.derivative())
    }
}
