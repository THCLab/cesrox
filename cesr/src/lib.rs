//! Encoding and parsing of CESR, the Composable Event Streaming
//! Representation, with the V2 code tables of the CESR specification.
//!
//! [`parse`] reads a whole stream, [`values`] reads one value at a time and
//! supports input that arrives in pieces, and [`parse_value`] reads a single
//! value. All of them take bytes, so message bodies in CBOR or MessagePack can
//! sit next to text-domain attachments, and groups may be in the text or the
//! binary domain; [`cold_start::cold_start`] tells which comes next.
//!
//! ```
//! use cesrox::{group::Group, parse, payload::Payload, Value};
//!
//! // a JSON body followed by an indexed controller signature group
//! let stream = br#"{"name":"John"}-KAWAACtbOtJRRB4ZpxAuXUbmFl5kJlvOg8bVWBSJcy-SKymfJbZpFZYwEDrQ1d8OW8kDbYQkCsc5JBz4gIq6kCtJrMN"#;
//! let values = parse(stream).unwrap();
//!
//! assert!(matches!(&values[0], Value::Payload(Payload::JSON(_))));
//! let Value::SpecificGroup(Group::IndexedControllerSignatures(sigs)) = &values[1] else {
//!     panic!("expected signatures")
//! };
//! assert_eq!(sigs[0].code.index.current(), 0);
//!
//! // values encode back to the same text
//! let encoded: Vec<u8> = values.iter().flat_map(Value::to_cesr).collect();
//! assert_eq!(encoded, stream);
//! ```
//!
//! Attachments written by cesrox before 2.0 are read with the
//! `legacy-v2beta` feature, on by default; see [`Counting`] and
//! `migrate`.

#![warn(missing_docs)]

pub mod derivation_code;
pub mod error;
pub mod group;
#[cfg(feature = "legacy-v2beta")]
pub mod migrate;
pub mod payload;
pub mod primitives;

pub mod cesr_proof;
pub mod cold_start;
pub mod conversion;
mod parsing;
pub mod universal_codes;
pub mod value;
pub mod variable_length;

pub use error::Error;
pub use value::Value;

/// A parsed item and the rest of the input after it.
pub type Parsed<'a, T> = Result<(T, &'a [u8]), Error>;

use parsing::{finish, Ctx};
use universal_codes::GenusCountCode;

/// How the counts of the attachment groups `-K`, `-L`, `-M`, `-O`, `-S`,
/// `-T` and `-Y` are read.
///
/// CESR V2 counts the quadlets (4 characters) a group occupies. cesrox
/// before 2.0 counted the items in the group and wrote current-only indexed
/// signatures in a different layout; streams and stored data in that format
/// are read with `Counting::LegacyItems` or recognised by
/// `Counting::Auto`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Counting {
    /// CESR V2.
    #[cfg_attr(not(feature = "legacy-v2beta"), default)]
    Quadlets,
    /// The format of cesrox before 2.0.
    #[cfg(feature = "legacy-v2beta")]
    LegacyItems,
    /// V2 wherever the stream shows it: inside `-A` and `-C` groups and
    /// after a V2 genus code. Elsewhere a group is read as V2 if its content
    /// splits exactly into whole items, and in the old format otherwise.
    #[cfg(feature = "legacy-v2beta")]
    #[default]
    Auto,
}

/// Parses one value at the start of `input`. Returns the value and the rest
/// of the input.
///
/// Returns [`Error::Incomplete`] when `input` ends inside the value.
pub fn parse_value(input: &[u8]) -> Parsed<'_, Value> {
    parse_value_with(input, Counting::default())
}

/// [`parse_value`] with an explicit way of reading group counts.
pub fn parse_value_with(input: &[u8], counting: Counting) -> Parsed<'_, Value> {
    finish(input, value::parse_value_at(input, Ctx::new(counting)))
}

/// Parses all of `input` into values. Fails if any part of it is not valid
/// CESR, including a value cut off at the end.
pub fn parse(input: &[u8]) -> Result<Vec<Value>, Error> {
    values(input).collect()
}

/// [`parse`] with an explicit way of reading group counts.
pub fn parse_with(input: &[u8], counting: Counting) -> Result<Vec<Value>, Error> {
    values_with(input, counting).collect()
}

/// Iterates over the values in `input`, stopping after the first error.
///
/// For input that arrives in pieces: on [`Error::Incomplete`], keep
/// [`Values::remaining`] and continue once more data has been appended.
pub fn values(input: &[u8]) -> Values<'_> {
    values_with(input, Counting::default())
}

/// [`values`] with an explicit way of reading group counts.
pub fn values_with(input: &[u8], counting: Counting) -> Values<'_> {
    Values {
        input,
        consumed: 0,
        failed: false,
        counting,
    }
}

/// Iterator returned by [`values`].
#[derive(Debug, Clone)]
pub struct Values<'a> {
    input: &'a [u8],
    consumed: usize,
    failed: bool,
    counting: Counting,
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
        match parse_value_with(self.input, self.counting) {
            Ok((value, rest)) => {
                self.consumed += self.input.len() - rest.len();
                self.input = rest;
                // a V2 genus code makes the rest of the stream V2
                if let Value::VersionGenus(GenusCountCode::Keri { major: 2, .. }) = value {
                    self.counting = Counting::Quadlets;
                }
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
