use nom::branch::alt;
use serde::Deserialize;

use crate::error::Error;

use self::message::{json_message, cbor_message, mgpk_message};
mod message;

pub trait Payload {
    fn to_vec(&self) -> Result<Vec<u8>, Error>;
}

/// Tries to parse each possible serialization until it succeeds
pub fn parse_payload<'a, D: Deserialize<'a>>(stream: &'a [u8]) -> nom::IResult<&[u8], D> {
    alt((json_message::<D>, cbor_message::<D>, mgpk_message::<D>))(stream)
}