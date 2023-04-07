use version::serialization_info::SerializationFormats;

use crate::derivation::HashFunctionCode;

pub trait SAD {
    fn compute_digest(
        &self,
        code: HashFunctionCode,
        serialization_format: SerializationFormats,
    ) -> Self;
}
