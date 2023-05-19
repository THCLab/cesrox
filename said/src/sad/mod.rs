pub use crate::version::format::SerializationFormats;
pub use cesrox::derivation_code::DerivationCode;

use crate::{derivation::HashFunctionCode};

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
