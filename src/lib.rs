pub mod codes;
pub mod error;
pub mod parsers;
pub mod primitives;
pub mod group;
pub mod payload;

use payload::Payload;

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
