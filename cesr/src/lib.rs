//! Encoding and parsing of CESR, the Composable Event Streaming
//! Representation.
//!
//! [`parse`] reads a whole stream, [`values`] reads one value at a time and
//! supports input that arrives in pieces, and [`parse_value`] reads a single
//! value. All of them take bytes, so message bodies in CBOR or MessagePack can
//! sit next to text-domain attachments.

pub mod derivation_code;
pub mod error;
pub mod group;
pub mod payload;
pub mod primitives;

#[cfg(feature = "cesr-proof")]
pub mod cesr_proof;
pub mod conversion;
mod parsing;
pub mod universal_codes;
pub mod value;
pub mod variable_length;

pub use error::Error;
pub use value::Value;

/// A parsed item and the rest of the input after it.
pub type Parsed<'a, T> = Result<(T, &'a [u8]), Error>;

use parsing::finish;

/// Parses one value at the start of `input`. Returns the value and the rest
/// of the input.
///
/// Returns [`Error::Incomplete`] when `input` ends inside the value.
pub fn parse_value(input: &[u8]) -> Parsed<'_, Value> {
    finish(input, value::parse_value_at(input, 0))
}

/// Parses all of `input` into values. Fails if any part of it is not valid
/// CESR, including a value cut off at the end.
pub fn parse(input: &[u8]) -> Result<Vec<Value>, Error> {
    values(input).collect()
}

/// Iterates over the values in `input`, stopping after the first error.
///
/// For input that arrives in pieces: on [`Error::Incomplete`], keep
/// [`Values::remaining`] and continue once more data has been appended.
pub fn values(input: &[u8]) -> Values<'_> {
    Values {
        input,
        consumed: 0,
        failed: false,
    }
}

/// Iterator returned by [`values`].
#[derive(Debug, Clone)]
pub struct Values<'a> {
    input: &'a [u8],
    consumed: usize,
    failed: bool,
}

impl<'a> Values<'a> {
    /// The part of the input not yet parsed.
    pub fn remaining(&self) -> &'a [u8] {
        self.input
    }
}

impl Iterator for Values<'_> {
    type Item = Result<Value, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.input.is_empty() {
            return None;
        }
        match parse_value(self.input) {
            Ok((value, rest)) => {
                self.consumed += self.input.len() - rest.len();
                self.input = rest;
                Some(Ok(value))
            }
            Err(error) => {
                self.failed = true;
                Some(Err(match error {
                    Error::At { offset, source } => Error::At {
                        offset: self.consumed + offset,
                        source,
                    },
                    other => other,
                }))
            }
        }
    }
}
