pub mod derivation_code;
pub mod error;
pub mod group;
pub mod payload;
pub mod primitives;
use std::sync::mpsc::SendError;
use std::sync::mpsc::Sender;

use crate::value::parse_value;
use crate::value::Value;

#[cfg(feature = "cesr-proof")]
pub mod cesr_proof;
pub mod conversion;
pub mod universal_codes;
pub mod value;

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

pub fn parse_one(stream: &str) -> Result<(&str, Value), ParsingError> {
    Ok(parse_value(stream)?)
}

pub fn parse_all(stream: &str) -> Result<(&str, Vec<Value>), ParsingError> {
    Ok(nom::multi::many0(parse_value)(stream)?)
}

pub fn parse_and_send(content: &str, tx: &Sender<Value>) -> Result<(), CESRError> {
    let mut buff = content;

    while !buff.is_empty() {
        match parse_value(buff) {
            Ok((rest, parsed)) => {
                tx.send(parsed)?;
                buff = rest;
            }
            Err(e) => {
                return Err(CESRError::ParsingError(ParsingError::from(e)));
            }
        }
    }

    Ok(())
}
