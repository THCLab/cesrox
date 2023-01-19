use std::{collections::HashMap, io::Cursor};

use nom::error::{make_error, ErrorKind};
use rmp_serde as serde_mgpk;
use serde::Deserialize;
use serde_json::Value;

use super::Payload;

pub(crate) fn json_message(s: &[u8]) -> nom::IResult<&[u8], Payload> {
    let mut stream = serde_json::Deserializer::from_slice(s).into_iter::<Value>();
    match stream.next() {
        Some(Ok(_event)) => Ok((
            &s[stream.byte_offset()..],
            Payload::JSON(s[..stream.byte_offset()].to_vec()),
        )),
        _ => Err(nom::Err::Error(make_error(s, ErrorKind::IsNot))),
    }
}

pub(crate) fn cbor_message(s: &[u8]) -> nom::IResult<&[u8], Payload> {
    let mut stream = serde_cbor::Deserializer::from_slice(s).into_iter::<serde_cbor::Value>();
    match stream.next() {
        Some(Ok(_event)) => Ok((
            &s[stream.byte_offset()..],
            Payload::CBOR(s[..stream.byte_offset()].to_vec()),
        )),
        _ => Err(nom::Err::Error(make_error(s, ErrorKind::IsNot))),
    }
}

pub(crate) fn mgpk_message(s: &[u8]) -> nom::IResult<&[u8], Payload> {
    let mut deser = serde_mgpk::Deserializer::new(Cursor::new(s));
    let deserialized: Result<HashMap<String, String>, _> = Deserialize::deserialize(&mut deser);
    match deserialized {
        Ok(_event) => Ok((
            &s[deser.get_ref().position() as usize..],
            Payload::MGPK(s[..deser.get_ref().position() as usize].to_vec()),
        )),
        _ => Err(nom::Err::Error(make_error(s, ErrorKind::IsNot))),
    }
}
