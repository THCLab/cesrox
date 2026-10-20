//! Errors of SAID handling.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, Serialize, Deserialize)]
/// Errors of reading and checking SAIDs.
pub enum Error {
    #[error("Incorrect data length: {0}")]
    /// The SAID text has the wrong length or pad bits.
    IncorrectLengthError(String),

    #[error("Deserialize error: {0}")]
    /// The data could not be deserialized.
    DeserializeError(String),

    #[error("Icorrect digest")]
    /// The digest does not match the data.
    IncorrectDigestError,

    #[error(transparent)]
    /// The SAID is not valid CESR.
    ParseError(#[from] cesrox::error::Error),
}
