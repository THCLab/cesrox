# cesrox

A Rust implementation of CESR, the Composable Event Streaming
Representation, as specified in the
[CESR specification](https://trustoverip.github.io/kswg-cesr-specification/)
(version 2 code tables).

## Protocol overview

The Composable Event Streaming Representation (CESR) is a dual text-binary
encoding format that has the unique property of text-binary concatenation
composability. This composability property enables the round trip conversion
en-masse of concatenated primitives between the text domain and binary domain
while maintaining separability of individual primitives. This enables convenient
usability in the text domain and compact transmission in the binary domain.
CESR primitives are self-framing. CESR supports self-framing group codes that
enable stream processing and pipelining in both the text and binary domains.
CESR supports composable text-binary encodings for general data types as well
as suites of cryptographic material. Popular cryptographic material suites
have compact encodings for efficiency while less compact encodings provide
sufficient extensibility to support all foreseeable types. CESR streams also
support interleaved JSON, CBOR, and MGPK serializations. CESR is a universal
encoding that uniquely provides dual text and binary domain representations
via composable conversion.

## What it covers

- all primitive, indexed signature, counter and universal group codes of the
  V2 code tables, in small and big forms;
- text (qb64) and binary (qb2) domains, interleaved with JSON, CBOR and
  MessagePack bodies, and detection of what a stream starts with;
- native CESR message bodies, field maps and lists;
- reading the attachment format of cesrox before 2.0 (feature
  `legacy-v2beta`, on by default) and migrating stored data to V2.

The crate encodes and decodes; it does not verify signatures or interpret
KERI events. Malformed input is reported as an error, never a panic.

## Usage

```rust
use cesrox::{parse, values, Error, Value};

// a whole stream
let values = parse(stream)?;

// a stream arriving in pieces
let mut reader = values(buffer);
for value in reader.by_ref() {
    match value {
        Ok(value) => handle(value),
        Err(Error::Incomplete { .. }) => break, // wait for more data
        Err(e) => return Err(e),
    }
}
let unread = reader.remaining();
```

Values encode back with `Value::to_cesr` (text) or `Value::to_qb2`
(binary). `Value::universal_group` builds groups, for example the attachment
group (`-C`) that should follow a message body.

### Streams written by cesrox before 2.0

Version 2 of CESR counts attachment groups in quadlets; cesrox before 2.0
counted items. The default `Counting::Auto` reads both; stored data should
be read with `Counting::LegacyItems` and converted with
`cesrox::migrate::migrate` or the `cesr-migrate` tool. Message bodies, and
so SAIDs and signatures, are not changed by the conversion. See
[MIGRATING.md](../MIGRATING.md).

## Test vectors

The crate is tested against shared CESR V2 test vectors from several
sources; see [test-vectors](../test-vectors/README.md).
