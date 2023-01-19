use thiserror::Error;
use core::num::ParseIntError;


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
}