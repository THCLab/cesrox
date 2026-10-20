//! The error type of the crate.

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
    /// The text does not start with a code from the table being read.
    #[error("unknown code")]
    UnknownCode,

    /// The text ends before the code is complete. Stream parsers report
    /// this as [`Error::Incomplete`].
    #[error("text too short for the code")]
    Truncated,

    /// The text has characters outside url-safe Base64, or does not
    /// decode.
    #[error("invalid base64")]
    InvalidBase64,

    /// A value or group does not have the size its code requires, or is
    /// too large to encode.
    #[error("incorrect data length: {0}")]
    IncorrectLength(String),

    /// The input breaks a CESR rule other than those above, such as a
    /// group whose content does not fill its count.
    #[error("invalid CESR: {0}")]
    Invalid(String),

    /// A JSON, CBOR or MessagePack message body is malformed.
    #[error("invalid payload: {0}")]
    Payload(String),

    /// The input ends inside a value; more input may complete it.
    #[error("input ends inside a value{}", needed.map(|n| format!(", {n} more bytes needed")).unwrap_or_default())]
    Incomplete {
        /// How many more bytes are needed, when known.
        needed: Option<usize>,
    },

    /// Groups nest deeper than the parser allows.
    #[error("groups nested more than {} levels deep", crate::value::MAX_NESTING)]
    NestingTooDeep,

    /// An error from stream parsing with the position of the failing
    /// value.
    #[error("{source} at byte {offset}")]
    At {
        /// Byte offset of the failing value in the input.
        offset: usize,
        /// The error itself.
        source: Box<Error>,
    },
}

impl From<DecodeError> for Error {
    fn from(_: DecodeError) -> Self {
        Error::InvalidBase64
    }
}
