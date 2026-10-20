//! Self-addressing data: types that hold their own SAID.

use crate::derivation::HashFunctionCode;
use crate::version::error::Error;
pub use crate::version::format::SerializationFormats;
pub use cesrox::derivation_code::DerivationCode;

/// Self-addressing data: a type with fields that hold its own SAID.
/// Types that serialize as a map can use [`crate::saidify_value`] instead
/// of implementing it.
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
