//! Errors of version strings and serialization.

use core::num::ParseIntError;
use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
/// Errors of version strings and serialization.
pub enum Error {
    #[error("Error during Serialization: {0}")]
    /// The message could not be serialized.
    SerializationError(String),

    // TODO: add line/col
    #[error("JSON Serialization error")]
    /// JSON serialization failed.
    JsonDeserError,

    #[error("CBOR Serialization error")]
    /// CBOR serialization failed.
    CborDeserError,

    #[error("MessagePack Serialization error")]
    /// MessagePack serialization failed.
    MsgPackDeserError,

    #[error("Deserialize error: {0}")]
    /// Data or a version string could not be read.
    DeserializeError(String),

    /// A number in a version string is not valid.
    #[error("Parse int error")]
    ParseInt(#[from] ParseIntError),

    #[error("Improper version string length {0}, should be 4")]
    /// A protocol code is not four characters long.
    VersionStringLength(String),

    #[error("No field {0} to hold the SAID")]
    /// A SAID field to be filled in is missing.
    MissingField(String),

    #[error("SAID does not bind the message: {0}")]
    /// A message's SAID fields are not the SAID of the message.
    InvalidSaid(String),
}
