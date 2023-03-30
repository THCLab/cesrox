use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum Error {
    #[error("Incorrect data length: {0}")]
    IncorrectLengthError(String),

    #[error("Deserialize error: {0}")]
    DeserializeError(String),

    #[error("Icorrect digest")]
    IncorrectDigestError,

    #[error(transparent)]
    ParseError(#[from] cesrox::error::Error),
}
