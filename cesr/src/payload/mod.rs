//! Message bodies in JSON, CBOR or MessagePack.

use crate::{
    conversion::check_first_three_bits,
    error::Error,
    parsing::{error, finish, PResult},
    Parsed,
};

use self::message::{cbor_message, json_message, mgpk_message};
mod message;

/// A message body in a serialisation that is not native CESR, kept as its
/// bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Payload {
    /// A JSON body.
    JSON(Vec<u8>),
    /// A CBOR body.
    CBOR(Vec<u8>),
    /// A MessagePack body.
    MGPK(Vec<u8>),
}

impl Payload {
    /// The serialised body.
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Payload::JSON(data) | Payload::CBOR(data) | Payload::MGPK(data) => data.clone(),
        }
    }
}

/// Parses a JSON, CBOR or MessagePack message body at the start of
/// `stream`, telling them apart by the first byte. Returns the body and the
/// rest of the input.
pub fn parse_payload(stream: &[u8]) -> Parsed<'_, Payload> {
    finish(stream, payload(stream))
}

pub(crate) fn payload(stream: &[u8]) -> PResult<'_, Payload> {
    let Some(first_byte) = stream.first() else {
        return error(stream, Error::Incomplete { needed: Some(1) });
    };
    match check_first_three_bits(first_byte) {
        0b011 => json_message(stream),
        0b100 => mgpk_message(stream),
        0b101 => cbor_message(stream),
        0b110 => mgpk_message(stream),
        _ => error(stream, Error::UnknownCode),
    }
}
