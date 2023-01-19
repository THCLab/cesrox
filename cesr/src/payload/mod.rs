use nom::branch::alt;

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
    alt((json_message, cbor_message, mgpk_message))(stream)
}
