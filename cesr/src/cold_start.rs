//! What a stream starts with, from its first three bits (the "cold start"
//! table of the CESR specification). Count codes in the text and binary
//! domains and JSON, CBOR and MessagePack bodies all start with different
//! bits, so a reader can tell them apart and switch between them mid-stream.

/// The kind of item a stream starts with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ColdStart {
    /// `0b000`: text-domain CESR with annotations (line breaks, comments).
    Annotated,
    /// `0b001`: a text-domain count code, `-`.
    TextCountCode,
    /// `0b010`: a text-domain op code, `_`.
    TextOpCode,
    /// `0b011`: a JSON body, `{`.
    Json,
    /// `0b100` or `0b110`: a MessagePack body (fixmap, map16 or map32).
    MessagePack,
    /// `0b101`: a CBOR body (map).
    Cbor,
    /// `0b111`: a binary-domain count code or op code.
    BinaryCountOrOpCode,
}

/// The kind of item `input` starts with, or `None` if it is empty.
pub fn cold_start(input: &[u8]) -> Option<ColdStart> {
    let first = input.first()?;
    Some(match first >> 5 {
        0b000 => ColdStart::Annotated,
        0b001 => ColdStart::TextCountCode,
        0b010 => ColdStart::TextOpCode,
        0b011 => ColdStart::Json,
        0b100 | 0b110 => ColdStart::MessagePack,
        0b101 => ColdStart::Cbor,
        _ => ColdStart::BinaryCountOrOpCode,
    })
}

/// Removes annotations from text-domain CESR: comments from `#` to the end
/// of the line and all spaces, tabs and line breaks. Meant for annotated
/// streams of count codes and primitives; message bodies inside them are not
/// protected.
pub fn deannotate(annotated: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(annotated.len());
    let mut in_comment = false;
    for &b in annotated {
        match b {
            b'\n' | b'\r' => in_comment = false,
            _ if in_comment => {}
            b'#' => in_comment = true,
            b' ' | b'\t' => {}
            _ => out.push(b),
        }
    }
    out
}

#[test]
fn every_tritet_is_classified() {
    assert_eq!(cold_start(b"\n"), Some(ColdStart::Annotated));
    assert_eq!(cold_start(b"-KAB"), Some(ColdStart::TextCountCode));
    assert_eq!(cold_start(b"_AAA"), Some(ColdStart::TextOpCode));
    assert_eq!(cold_start(b"{}"), Some(ColdStart::Json));
    assert_eq!(cold_start(&[0x85]), Some(ColdStart::MessagePack));
    assert_eq!(cold_start(&[0xa5]), Some(ColdStart::Cbor));
    assert_eq!(cold_start(&[0xde]), Some(ColdStart::MessagePack));
    // `-` in the binary domain: sextet 62, 0b111110
    assert_eq!(cold_start(&[0xf8]), Some(ColdStart::BinaryCountOrOpCode));
    assert_eq!(cold_start(b""), None);
}

#[test]
fn annotations_are_removed() {
    let annotated = b"-KAW  # signatures\n    AACZ0jw  # first\r\n\tAB  \n";
    assert_eq!(deannotate(annotated), b"-KAWAACZ0jwAB");
}
