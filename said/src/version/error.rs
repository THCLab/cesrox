use core::num::ParseIntError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error during Serialization: {0}")]
    SerializationError(String),

    // TODO: add line/col
    #[error("JSON Serialization error")]
    JsonDeserError,

    #[error("CBOR Serialization error")]
    CborDeserError,

    #[error("MessagePack Serialization error")]
    MsgPackDeserError,

    #[error("Deserialize error: {0}")]
    DeserializeError(String),

    #[error("Parse int error")]
    Disconnect(#[from] ParseIntError),

    #[error("Improper version string length {0}, should be 4")]
    VersionStringLength(String),
}
