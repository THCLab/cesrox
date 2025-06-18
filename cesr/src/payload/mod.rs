use nom::error::{make_error, ErrorKind};

use crate::conversion::check_first_three_bits;

use self::message::{cbor_message, json_message, mgpk_message};
mod message;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload {
    JSON(Vec<u8>),
    CBOR(Vec<u8>),
    MGPK(Vec<u8>),
}

impl Payload {
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Payload::JSON(data) | Payload::CBOR(data) | Payload::MGPK(data) => data.clone(),
        }
    }
}

/// Tries to parse each possible serialization until it succeeds
pub fn parse_payload(stream: &[u8]) -> nom::IResult<&[u8], Payload> {
    let first_byte = stream
        .first()
        .ok_or(nom::Err::Error(make_error(stream, ErrorKind::Eof)))?;
    let first_three_bits = check_first_three_bits(first_byte);
    match first_three_bits {
        0b011 => json_message(stream),
        0b100 => mgpk_message(stream),
        0b101 => cbor_message(stream),
        0b110 => mgpk_message(stream),
        _ => Err(nom::Err::Error(make_error(stream, ErrorKind::IsNot))),
    }
}
