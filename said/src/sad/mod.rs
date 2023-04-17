pub use version::serialization_info::SerializationFormats;
pub use cesrox::derivation_code::DerivationCode;

use crate::derivation::HashFunctionCode;
pub use sad_macros;

pub trait SAD {
    fn compute_digest(
        &self,
        code: HashFunctionCode,
        serialization_format: SerializationFormats,
    ) -> Self;

    fn derivation_data(
        &self,
        code: &HashFunctionCode,
        serialization_format: &SerializationFormats,
    ) -> Vec<u8>;
}
