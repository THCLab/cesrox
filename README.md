# CESRox

CESRox is a Rust based implementation of [CESR](https://weboftrust.github.io/ietf-cesr/draft-ssmith-cesr.html) protocol.

## Usage

See [integration tests](https://github.com/THCLab/cesrox/blob/master/tests/client.rs).

## Implementation assumptions, trade-offs and limitations

- it deserializes CESR streams into payloads with attachments and serializes payloads with attachments into CESR streams;
- it is agnostic to any data model as it imposes on the consumer to provide payloads already represented in one of CESR-compliant representation (JSON, MGPK, CBOR) – thus consumer data model stays encapsulated within consumer codebase;
- it aims to be exposed via FFI layers to the other programming languages and therefore it heavily relies on primitives rather than complex object structures – primitives enable almost seamless integrations as opposed to complex object structures. It is also the direct consequence of imposing consumer data model (de)serialization on her side.
- it requires POSIX-compliant OS, yet it is possible to go with the `no-std` approach (PR's are welcome);
- due to the nature of parsing CESR streams that are computation intense rather than i/o intense, it is intentionally provided without any `Async`-compliant capabilities.

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


## License

EUPL 1.2

https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12

See LICENSE.md
