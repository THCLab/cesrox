use std::str::FromStr;

use super::{HashFunction, SelfAddressingIdentifier};

use cesrox::{
    conversion::from_text_to_bytes,
    derivation_code::DerivationCode,
    primitives::{
        codes::{self_addressing::SelfAddressing, PrimitiveCode},
        CesrPrimitive, Digest,
    },
};

impl HashFunction {
    pub fn get_len(&self) -> usize {
        let cesr_code: SelfAddressing = self.into();
        cesr_code.full_size()
    }
}

impl CesrPrimitive for SelfAddressingIdentifier {
    fn derivative(&self) -> Vec<u8> {
        self.digest.clone()
    }
    fn derivation_code(&self) -> PrimitiveCode {
        PrimitiveCode::SelfAddressing((&self.derivation).into())
    }
}

impl FromStr for SelfAddressingIdentifier {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = SelfAddressing::from_str(s)?;
        let c_len = code.code_size();
        let length_error = || Self::Err::IncorrectLengthError(s.into());
        if s.len() != code.full_size() {
            return Err(length_error());
        }
        let text = s.get(c_len..).ok_or_else(length_error)?;
        let decoded = from_text_to_bytes(text)?
            .get(c_len..)
            .ok_or_else(length_error)?
            .to_vec();

        Ok(Self::new(code.into(), decoded))
    }
}

impl From<Digest> for SelfAddressingIdentifier {
    fn from((code, digest): Digest) -> Self {
        SelfAddressingIdentifier::new(code.into(), digest)
    }
}

impl From<SelfAddressingIdentifier> for Digest {
    fn from(val: SelfAddressingIdentifier) -> Self {
        (val.derivation.to_owned().into(), val.derivative())
    }
}
