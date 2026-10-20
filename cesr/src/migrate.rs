//! Converts CESR stored in the format of cesrox before 2.0 to CESR V2.
//!
//! The old format counted the items of attachment groups and wrote
//! current-only indexed signatures in a different layout. Bodies are not
//! touched, and signatures only cover bodies, so migrated messages keep
//! their SAIDs, identifiers and signatures.

use crate::{
    error::Error,
    parse_with,
    universal_codes::{UniversalCode, UniversalGroupCode},
    Counting, Value,
};

/// How [`migrate`] reads and writes.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// How the input is read. Stored data is in the old format, so the
    /// default reads it as such; [`Counting::Auto`] also accepts input
    /// that is partly V2 already.
    pub counting: Counting,
    /// Wrap the attachment groups that follow each message body in an
    /// attachment group (`-C`). Wrapped attachments are unambiguously V2
    /// for every reader.
    pub wrap_attachments: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            counting: Counting::LegacyItems,
            wrap_attachments: true,
        }
    }
}

/// Result of [`migrate`].
#[derive(Clone, Debug, PartialEq)]
pub struct Migration {
    /// The stream in CESR V2.
    pub output: Vec<u8>,
    /// Whether the input needed converting; already-V2 input is returned
    /// unchanged.
    pub changed: bool,
}

/// Converts `input` to CESR V2 and checks that the result reads back, as
/// V2, to the same values.
pub fn migrate(input: &[u8], options: &Options) -> Result<Migration, Error> {
    let values = match parse_with(input, options.counting) {
        Ok(values) => values,
        // input that does not read in the old format may be V2 already
        Err(legacy) => {
            return match parse_with(input, Counting::Quadlets) {
                Ok(_) => Ok(Migration {
                    output: input.to_vec(),
                    changed: false,
                }),
                Err(_) => Err(legacy),
            }
        }
    };

    let migrated = if options.wrap_attachments {
        wrap_attachments(values.clone())?
    } else {
        values.clone()
    };
    let output: Vec<u8> = migrated.iter().flat_map(Value::to_cesr).collect();

    let check = parse_with(&output, Counting::Quadlets)
        .map_err(|e| Error::Invalid(format!("migrated stream does not read as V2: {e}")))?;
    if unwrap_attachments(check) != unwrap_attachments(values) {
        return Err(Error::Invalid(
            "migrated stream reads differently from the input".into(),
        ));
    }
    Ok(Migration {
        changed: output != input,
        output,
    })
}

/// Puts each run of attachment groups into one attachment group (`-C`).
fn wrap_attachments(values: Vec<Value>) -> Result<Vec<Value>, Error> {
    let mut out = vec![];
    let mut run = vec![];
    for value in values {
        match value {
            Value::SpecificGroup(_) => run.push(value),
            other => {
                flush(&mut run, &mut out)?;
                out.push(other);
            }
        }
    }
    flush(&mut run, &mut out)?;
    Ok(out)
}

fn flush(run: &mut Vec<Value>, out: &mut Vec<Value>) -> Result<(), Error> {
    if !run.is_empty() {
        out.push(Value::universal_group(
            UniversalCode::Attachments,
            std::mem::take(run),
        )?);
    }
    Ok(())
}

/// The values with attachment groups replaced by their content, for
/// comparing wrapped and unwrapped streams.
fn unwrap_attachments(values: Vec<Value>) -> Vec<Value> {
    values
        .into_iter()
        .flat_map(|value| match value {
            Value::UniversalGroup(
                UniversalGroupCode::Group {
                    code: UniversalCode::Attachments,
                    ..
                },
                inner,
            ) => unwrap_attachments(inner),
            other => vec![other],
        })
        .collect()
}
