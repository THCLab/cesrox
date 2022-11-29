pub mod codes;
pub mod error;
pub mod primitives;
pub mod group;
pub mod payload;

use group::parsers::parse_group;
use nom::multi::many0;
use payload::{Payload, parse_payload};
use serde::Deserialize;

use self::error::Error;

use self::group::Group;

pub mod parsing;
#[cfg(feature = "cesr-proof")]
pub mod path;
pub mod value;


#[derive(Clone, Debug, PartialEq)]
pub struct ParsedData<P> {
    pub payload: P,
    pub attachments: Vec<Group>,
}

impl<P: Payload> ParsedData<P> {
    pub fn to_cesr(&self) -> Result<Vec<u8>, Error> {
        let attachments = self
            .attachments
            .iter()
            .fold(String::default(), |acc, att| {
                [acc, att.to_cesr_str()].concat()
            })
            .as_bytes()
            .to_vec();
        Ok([self.payload.to_vec()?, attachments].concat())
    }
}


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
