use crate::derivation::HashFunctionCode;
pub use crate::version::format::SerializationFormats;
pub use cesrox::derivation_code::DerivationCode;

#[cfg(feature = "macros")]
pub use sad_macros::SAD;

pub trait SAD {
    fn compute_digest(&mut self, derivation: &HashFunctionCode, format: &SerializationFormats);

    fn derivation_data(&self, derivation: &HashFunctionCode, format: &SerializationFormats) -> Vec<u8>;
}
