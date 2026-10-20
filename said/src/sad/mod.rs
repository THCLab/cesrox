use crate::derivation::HashFunctionCode;
use crate::version::error::Error;
pub use crate::version::format::SerializationFormats;
pub use cesrox::derivation_code::DerivationCode;

#[cfg(feature = "macros")]
pub use sad_macros::SAD;

/// Self-addressing data: a type with fields that hold its own SAID.
/// Usually derived with `#[derive(SAD)]` and `#[said]` on the SAID fields.
pub trait SAD {
    /// Computes the SAID in `format` and stores it in the SAID fields.
    fn compute_digest(
        &mut self,
        derivation: &HashFunctionCode,
        format: &SerializationFormats,
    ) -> Result<(), Error>;

    /// The serialization the SAID is computed over: the SAID fields hold `#`
    /// placeholders, and a version string, if any, has the kind and size
    /// of this serialization.
    fn derivation_data(
        &self,
        derivation: &HashFunctionCode,
        format: &SerializationFormats,
    ) -> Result<Vec<u8>, Error>;
}
