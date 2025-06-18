pub mod derivation_code;
pub mod error;
pub mod group;
pub mod payload;
pub mod primitives;
use std::sync::mpsc::Sender;

use crate::error::CESRError;
use crate::error::ParsingError;
use crate::value::parse_value;
use crate::value::Value;

#[cfg(feature = "cesr-proof")]
pub mod cesr_proof;
pub mod conversion;
pub mod universal_codes;
pub mod value;

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
