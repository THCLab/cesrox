pub use crate::version::format::SerializationFormats;
pub use cesrox::derivation_code::DerivationCode;

use crate::derivation::HashFunctionCode;

#[cfg(feature = "macros")]
pub use sad_macros::SAD;

pub trait SAD {
    fn compute_digest(
        &mut self,
        code: HashFunctionCode,
    );

    fn derivation_data(
        &self,
        code: &HashFunctionCode,
    ) -> Vec<u8>;
}
