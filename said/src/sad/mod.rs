pub use cesrox::derivation_code::DerivationCode;
pub use version::serialization_info::SerializationFormats;

use crate::derivation::HashFunctionCode;

#[cfg(feature = "macros")]
pub use sad_macros::SAD;

pub trait SAD {
    fn compute_digest(
        &mut self,
        code: HashFunctionCode,
        serialization_format: SerializationFormats,
    );

    fn derivation_data(
        &self,
        code: &HashFunctionCode,
        serialization_format: &SerializationFormats,
    ) -> Vec<u8>;
}
