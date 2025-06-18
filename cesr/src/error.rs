use std::sync::mpsc::SendError;

use base64::DecodeError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::value::Value;

#[derive(Error, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Error {
    #[error("Base64 Decoding error")]
    Base64DecodingError,

    #[error("Unknown code")]
    UnknownCodeError,

    #[error("Empty code")]
    EmptyCodeError,

    #[error("Empty stream")]
    EmptyStreamError,

    #[error("Incorrect data length: {0}")]
    IncorrectLengthError(String),

    #[error("Payload serialization error")]
    PayloadSerializationError,
}

impl From<base64::DecodeError> for Error {
    fn from(_: DecodeError) -> Self {
        Error::Base64DecodingError
    }
}

#[derive(thiserror::Error, Debug)]
pub enum CESRError {
    #[error("Can't parse stream: {0}")]
    ParsingError(ParsingError),

    #[error(transparent)]
    SendingError(#[from] SendError<Value>),
}

#[derive(Debug, thiserror::Error)]
pub enum ParsingError {
    #[error("Incomplete stream: {0}")]
    IncompleteStream(String),
    #[error("Error while parsing: {0}")]
    Error(String),
    #[error("Parsing failure: {0}")]
    Failure(String),
}

impl From<nom::Err<nom::error::Error<&str>>> for ParsingError {
    fn from(err: nom::Err<nom::error::Error<&str>>) -> Self {
        match err {
            nom::Err::Incomplete(_) => {
                ParsingError::IncompleteStream("Stream is incomplete".to_string())
            }
            nom::Err::Error(e) => ParsingError::Error(e.to_string()),
            nom::Err::Failure(e) => ParsingError::Failure(e.to_string()),
        }
    }
}
