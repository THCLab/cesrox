//! Plumbing shared by the stream parsers. nom stays an implementation
//! detail: parsers return [`PResult`] internally and the public functions
//! convert it to [`Error`] with [`finish`].

use nom::error::{ErrorKind, ParseError};

use crate::{error::Error, Counting, Parsed};

/// Where a parser is in the stream: how deep in nested groups, and how
/// counts of attachment groups are read there.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Ctx {
    pub depth: usize,
    pub counting: Counting,
}

impl Ctx {
    pub fn new(counting: Counting) -> Self {
        Ctx { depth: 0, counting }
    }

    /// Context for something nested one level deeper.
    pub fn nested(self) -> Self {
        Ctx {
            depth: self.depth + 1,
            ..self
        }
    }

    pub fn with_counting(self, counting: Counting) -> Self {
        Ctx { counting, ..self }
    }
}

/// Inside a counted group the content is complete, so running out of it
/// means the group is malformed rather than that more input is needed.
pub(crate) fn framed<T>(result: PResult<'_, T>) -> PResult<'_, T> {
    result.map_err(|e| {
        e.map(|mut f| {
            if let Error::Incomplete { .. } = f.error {
                f.error = Error::Invalid("group content ends inside a value".into());
            }
            f
        })
    })
}

/// A parse failure at `input`, the remaining input where it happened.
#[derive(Debug)]
pub(crate) struct Failure<'a> {
    pub input: &'a [u8],
    pub error: Error,
}

impl<'a> ParseError<&'a [u8]> for Failure<'a> {
    fn from_error_kind(input: &'a [u8], kind: ErrorKind) -> Self {
        let error = match kind {
            // complete-input combinators report running out of data as Eof
            ErrorKind::Eof | ErrorKind::Complete => Error::Incomplete { needed: None },
            ErrorKind::TooLarge => Error::NestingTooDeep,
            other => Error::Invalid(other.description().to_string()),
        };
        Failure { input, error }
    }

    fn append(_: &'a [u8], _: ErrorKind, other: Self) -> Self {
        other
    }
}

pub(crate) type PResult<'a, T> = nom::IResult<&'a [u8], T, Failure<'a>>;

/// A recoverable failure: alternatives may still be tried.
pub(crate) fn error<T>(input: &[u8], error: Error) -> PResult<'_, T> {
    Err(nom::Err::Error(Failure { input, error }))
}

/// A failure that stops parsing, even inside `many0` and alternatives.
pub(crate) fn failure<T>(input: &[u8], error: Error) -> PResult<'_, T> {
    Err(nom::Err::Failure(Failure { input, error }))
}

/// The leading ASCII part of `input`, where CESR text-domain codes live.
pub(crate) fn ascii(input: &[u8]) -> &str {
    let end = input
        .iter()
        .position(|b| !b.is_ascii())
        .unwrap_or(input.len());
    // ASCII bytes are always valid UTF-8
    std::str::from_utf8(&input[..end]).unwrap_or_default()
}

/// Turns a failed code lookup into a stream error: running out of input
/// means more data is needed, anything else is an unknown code.
pub(crate) fn code_error(input: &[u8], error: Error) -> Error {
    match error {
        Error::Truncated if ascii(input).len() == input.len() => Error::Incomplete { needed: None },
        Error::Truncated => Error::UnknownCode,
        other => other,
    }
}

/// Converts a parser result into the public form, adding the byte offset of
/// the failure within `original`.
pub(crate) fn finish<'a, T>(original: &'a [u8], result: PResult<'a, T>) -> Parsed<'a, T> {
    match result {
        Ok((rest, value)) => Ok((value, rest)),
        Err(nom::Err::Incomplete(needed)) => Err(Error::Incomplete {
            needed: match needed {
                nom::Needed::Size(n) => Some(n.get()),
                nom::Needed::Unknown => None,
            },
        }),
        Err(nom::Err::Error(f) | nom::Err::Failure(f)) => Err(match f.error {
            incomplete @ Error::Incomplete { .. } => incomplete,
            error => Error::At {
                offset: original.len() - f.input.len(),
                source: Box::new(error),
            },
        }),
    }
}

/// Runs a parser on text and returns `(rest, value)`, the shape the older
/// unit tests are written against.
#[cfg(test)]
pub(crate) fn on_text<'a, T>(
    s: &'a str,
    parser: impl FnOnce(&'a [u8]) -> PResult<'a, T>,
) -> Result<(&'a str, T), Error> {
    let (value, rest) = finish(s.as_bytes(), parser(s.as_bytes()))?;
    Ok((std::str::from_utf8(rest).unwrap(), value))
}
