pub mod derivation_code;
pub mod error;
pub mod group;
pub mod payload;
pub mod primitives;
use std::sync::mpsc::SendError;
use std::sync::mpsc::Sender;

use crate::error::Error;
use group::parsers::parse_group;
use nom::multi::many0;
use payload::{parse_payload, Payload};

use self::group::Group;

#[cfg(feature = "cesr-proof")]
pub mod cesr_proof;
pub mod conversion;
pub mod value;

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum ParsingError {
    #[error("Can't parse stream: {0}")]
    ParsingError(String),

    #[error(transparent)]
    SendingError(#[from] SendError<ParsedData>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct ParsedData {
    pub payload: Payload,
    pub attachments: Vec<Group>,
}

impl ParsedData {
    pub fn to_cesr(&self) -> Result<Vec<u8>, Error> {
        let attachments = self
            .attachments
            .iter()
            .fold(String::default(), |acc, att| {
                [acc, att.to_cesr_str()].concat()
            })
            .as_bytes()
            .to_vec();
        Ok([self.payload.to_vec(), attachments].concat())
    }
}

pub fn parse(stream: &[u8]) -> nom::IResult<&[u8], ParsedData> {
    let (rest, payload) = parse_payload(stream)?;
    let (rest, attachments) = many0(parse_group)(rest)?;

    Ok((
        rest,
        ParsedData {
            payload,
            attachments,
        },
    ))
}

pub fn parse_many(stream: &[u8]) -> nom::IResult<&[u8], Vec<ParsedData>> {
    many0(parse)(stream)
}

pub fn parse_and_send(content: &[u8], tx: &Sender<ParsedData>) -> Result<(), ParsingError> {
    let mut buff = content;

    while !buff.is_empty() {
        match parse(buff) {
            Ok((rest, parsed)) => {
                tx.send(parsed)?;
                buff = rest;
            }
            Err(_) => {
                return Err(ParsingError::ParsingError(
                    String::from_utf8_lossy(buff).into_owned(),
                ));
            }
        }
    }

    Ok(())
}
