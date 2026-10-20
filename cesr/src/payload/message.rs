use std::io::Cursor;

use rmp_serde as serde_mgpk;
use serde::{de::IgnoredAny, Deserialize};
use serde_json::Value;

use super::Payload;
use crate::{
    error::Error,
    parsing::{error, PResult},
};

pub(crate) fn json_message(s: &[u8]) -> PResult<'_, Payload> {
    let mut stream = serde_json::Deserializer::from_slice(s).into_iter::<Value>();
    match stream.next() {
        Some(Ok(_event)) => Ok((
            &s[stream.byte_offset()..],
            Payload::JSON(s[..stream.byte_offset()].to_vec()),
        )),
        Some(Err(e)) if e.is_eof() => error(s, Error::Incomplete { needed: None }),
        Some(Err(e)) => error(s, Error::Payload(format!("JSON: {e}"))),
        None => error(s, Error::Incomplete { needed: None }),
    }
}

pub(crate) fn cbor_message(s: &[u8]) -> PResult<'_, Payload> {
    let mut stream = serde_cbor::Deserializer::from_slice(s).into_iter::<serde_cbor::Value>();
    match stream.next() {
        Some(Ok(_event)) => Ok((
            &s[stream.byte_offset()..],
            Payload::CBOR(s[..stream.byte_offset()].to_vec()),
        )),
        Some(Err(e)) if e.is_eof() => error(s, Error::Incomplete { needed: None }),
        Some(Err(e)) => error(s, Error::Payload(format!("CBOR: {e}"))),
        None => error(s, Error::Incomplete { needed: None }),
    }
}

pub(crate) fn mgpk_message(s: &[u8]) -> PResult<'_, Payload> {
    let mut deser = serde_mgpk::Deserializer::new(Cursor::new(s));
    // skips exactly one value of any shape
    let deserialized = IgnoredAny::deserialize(&mut deser);
    match deserialized {
        Ok(_event) => Ok((
            &s[deser.get_ref().position() as usize..],
            Payload::MGPK(s[..deser.get_ref().position() as usize].to_vec()),
        )),
        Err(e) => error(s, Error::Payload(format!("MessagePack: {e}"))),
    }
}
