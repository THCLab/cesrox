use nom::{multi::many0};
use serde::Deserialize;

use crate::{ParsedData, group::parsers::parse_group, payload::parse_payload};


pub mod primitives;

pub fn parse<'a, P: Deserialize<'a>>(stream: &'a [u8]) -> nom::IResult<&[u8], ParsedData<P>> {
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

pub fn parse_many<'a, P: Deserialize<'a>>(
    stream: &'a [u8],
) -> nom::IResult<&[u8], Vec<ParsedData<P>>> {
    many0(parse::<P>)(stream)
}
