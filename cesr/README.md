# CESRox

CESRox is a Rust based implementation of [CESR](https://weboftrust.github.io/ietf-cesr/draft-ssmith-cesr.html) protocol.

## Protocol overview

The Composable Event Streaming Representation (CESR) is dual text-binary
encoding format that has the unique property of text-binary concatenation
composability. This composability property enables the round trip conversion
en-masse of concatenated primitives between the text domain and binary domain
while maintaining separability of individual primtives. This enables convenient
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

## Implementation assumptions, trade-offs and limitations

- it deserializes CESR streams into payloads with attachments and serializes payloads with attachments into CESR streams;
- it is agnostic to any data model as it imposes on the consumer to provide payloads already represented in one of the CESR-compliant representations (JSON, MGPK, CBOR) – thus consumer data model stays encapsulated within the consumer codebase (and the consumer decides with which representation to go);
- it aims to be exposed via FFI layers to the other programming languages. Therefore, it heavily relies on primitives rather than complex object structures – primitives enable almost seamless integrations as opposed to complex object structures. It is also the direct consequence of imposing consumer data model (de)serialization on her side;
- it requires POSIX-compliant OS, yet it is possible to go with the `no-std` approach for non-POSIX support (PRs are welcome);
- due to the nature of parsing CESR streams that are computationally intense rather than i/o intense, it is intentionally provided without any `Async`-compliant capabilities.

## Usage

For CESRox usage examples, see [integration tests](https://github.com/THCLab/cesrox/blob/master/cesr/tests/client.rs).
