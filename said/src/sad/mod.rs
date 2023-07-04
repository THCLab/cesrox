pub use crate::version::format::SerializationFormats;
pub use cesrox::derivation_code::DerivationCode;

#[cfg(feature = "macros")]
pub use sad_macros::SAD;

pub trait SAD {
    fn compute_digest(&mut self);

    fn derivation_data(&self) -> Vec<u8>;
}
