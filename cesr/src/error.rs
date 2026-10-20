use base64::DecodeError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors returned when encoding, decoding or parsing CESR.
///
/// Errors from stream parsing are wrapped in [`Error::At`], which gives the
/// byte offset of the failing value in the input, except for
/// [`Error::Incomplete`], which means the input ended inside a value.
#[derive(Error, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Error {
    #[error("unknown code")]
    UnknownCode,

    #[error("text too short for the code")]
    Truncated,

    #[error("invalid base64")]
    InvalidBase64,

    #[error("incorrect data length: {0}")]
    IncorrectLength(String),

    #[error("invalid CESR: {0}")]
    Invalid(String),

    #[error("invalid payload: {0}")]
    Payload(String),

    #[error("input ends inside a value{}", needed.map(|n| format!(", {n} more bytes needed")).unwrap_or_default())]
    Incomplete { needed: Option<usize> },

    #[error("groups nested more than {} levels deep", crate::value::MAX_NESTING)]
    NestingTooDeep,

    #[error("{source} at byte {offset}")]
    At { offset: usize, source: Box<Error> },
}

impl From<DecodeError> for Error {
    fn from(_: DecodeError) -> Self {
        Error::InvalidBase64
    }
}
