# Migrating to cesrox and said 2.0

Version 2.0 implements the CESR V2 code tables in full. That changes how
attachments are written, and the API was reworked at the same time. This
guide lists what callers have to change and how to roll the new wire format
out to running systems.

## Wire format

CESR V2 differs from what cesrox wrote before 2.0:

- **Group counts are quadlets.** The count of `-K`, `-L`, `-M`, `-O`, `-S`,
  `-T` and `-Y` is the size of the group in 4-character quadlets, not the
  number of items: one Ed25519 signature is `-KAW`, no longer `-KAB`.
- **Current-only indexed signatures** (`0B`, `2B`, `2D`, `2R`, `3B`) carry
  the index in the first soft characters, and the encoder picks the smallest
  code that holds the index.
- **Sequence numbers** in `-S`, `-T`, `-O` and `-X` are written as Number
  primitives (`MAAB`), no longer as 24-character salts; both are read.
- **Non-canonical text is rejected:** non-zero pad bits and `=`.

Message bodies are not affected, so SAIDs, identifiers and signatures stay
valid. AIDs do not have to change and KELs do not have to be re-signed.

Indexed ECDSA P-256 signature codes (`Q`, `R`, `2Q`, `2R`) are unchanged;
they are not in the specification yet.

### Reading the old format

The `legacy-v2beta` feature, on by default, reads the old format:

- `Counting::Auto`, the default of `parse`, `values` and `parse_value`,
  reads V2 inside `-A` and `-C` groups and after a V2 genus code, and
  elsewhere reads a group as V2 only if its content splits into whole
  items, falling back to the old format. One case is ambiguous: an old
  group whose item count equals the quadlet size of its items, such as
  exactly 22 Ed25519 signatures.
- `Counting::LegacyItems` reads stored data that is known to be old; use it
  with `parse_with`, `values_with` or `parse_group_with`.
- `Group::to_legacy_cesr_str` writes the old format, for peers that have not
  been upgraded.

### Converting stored data

`cesrox::migrate::migrate` converts a stream to V2, wrapping each message's
attachments in an attachment group (`-C`), checks that the result reads
back the same, and leaves V2 input unchanged. The `cesr-migrate` tool does
the same for files:

```sh
cesr-migrate --check kel.cesr          # exit status 1: needs migrating
cesr-migrate kel.cesr -o kel-v2.cesr
```

### Rolling out

1. Upgrade the readers first; with the default features they read both
   formats.
2. Keep writing the old format with `Group::to_legacy_cesr_str` until every
   peer is upgraded, then switch to `Group::to_cesr_str`.
3. Wrap the attachments that follow a message body in `-C`
   (`Value::universal_group(UniversalCode::Attachments, ..)`); readers then
   never have to guess the format.
4. Convert stored CESR with the migration. Data that cannot be rewritten,
   such as signatures embedded in documents, stays readable as long as the
   `legacy-v2beta` feature is enabled.

## cesrox API

### Parsing

| Before | Now |
|---|---|
| `parse_all(&str) -> Result<(&str, Vec<Value>), ParsingError>` | `parse(&[u8]) -> Result<Vec<Value>, Error>`; fails on any invalid or cut-off input |
| `parse_one(&str)` | `parse_value(&[u8]) -> Parsed<Value>`, i.e. `Result<(Value, &[u8]), Error>` |
| `parse_and_send` | iterate `values(&[u8])`; on `Error::Incomplete` keep `Values::remaining()` and continue with more data |
| `group::parsers::parse_group(&str)` | `group::parse_group(&[u8]) -> Parsed<Group>` |
| `primitives::parsers::parse_primitive::<C>(&str)` | `primitives::parse_primitive::<C>(&[u8]) -> Parsed<Primitive<C>>` |
| `payload::parse_payload` returning `nom::IResult` | returns `Parsed<Payload>` |
| `group_code`, `identifier`, `serial_number_parser`, `timestamp_parser`, ... | crate-internal; use `FromStr` on the code types |

Inputs are bytes, so streams with CBOR or MessagePack bodies and
binary-domain groups parse; text callers pass `s.as_bytes()`.

### Errors

`ParsingError` and `CESRError` are gone; everything returns
`cesrox::Error`. Variants were renamed: `UnknownCodeError` to
`UnknownCode`, `EmptyCodeError` to `Truncated`, `IncorrectLengthError` to
`IncorrectLength`, `Base64DecodingError` to `InvalidBase64`. Stream errors
come as `Error::At { offset, source }`, or `Error::Incomplete` when the
input ends inside a value.

### Types

- Enums that later CESR versions can extend are `#[non_exhaustive]`
  (`Value`, `Group`, `GroupCode`, `Payload`, `PrimitiveCode`, `Basic`,
  `SelfSigning`, `SeedCode`, the universal and variable-length codes, and
  `Error`); `match` needs a wildcard arm.
- The tuple aliases are structs: `Primitive<C> { code, raw }` with
  `Digest`, `Signature`, `IndexedSignature`, `PublicKey`, `Identifier` and
  `Nonce` (formerly `SaltyNounce`) as its instances. `Primitive::new` and
  `From<(code, raw)>` build them; replace `.0` and `.1` with `.code` and
  `.raw`.
- Group entries are named structs: `NontransReceiptCouple { key, signature }`,
  `SealSourceCouple { sn, digest }`, `FirstSeenReplayCouple { fnu, timestamp }`,
  `AnchoringEventSeal { prefix, sn, digest }`,
  `TransLastIdxSigGroup { prefix, signatures }`.
- `Group::FirstSeenReplyCouples` and `GroupCode::FirstSeenReplyCouples` are
  `FirstSeenReplayCouples`.
- Sequence numbers are `u128`, indexes of indexed signatures `u32`, counts
  of `GroupCode` and universal groups `u32`.
- `Value::Primitive` holds a `Primitive<PrimitiveCode>`.
- `TagCode` is a struct built with `TagCode::new(text)` for tags of 1 to 11
  characters.
- `UniversalGroupCode::Group { code: UniversalCode, quadlets }` replaces
  `OverrideAllowed` and `OverrideNotAllowed`.
- The variable-length module is public; `SmallVariableLengthCode` and
  `LargeVariableLengthCode` are replaced by `VariableLengthType`, and the
  non-standard `G` code is removed.
- `VariableLengthPrimitive::create_from_str`, `create_from_bytes`,
  `MaterialPath::new` and `MaterialPath::create_from_str` return `Result`.
- `conversion::b64_to_num` is generic over its result type; `num_to_b64`
  takes any unsigned integer. `adjust_with_num` and `check_first_three_bits`
  are no longer public.
- The `cesr-proof` feature does nothing any more; pathed material (`-P`) is
  always available.

## said API

- `SerializationInfo` reads and writes V2 version strings
  (`KERICAACAAJSONAABk.`) for protocol version 2 and later. It has a
  `genus_version` field, the minor version is `u16`, and parsing is strict.
- `ProtocolVersion::new(prefix, major, minor)` takes the major version
  first.
- `SerializationFormats` has a `CESR` variant, which is read but not
  serialized, and is `#[non_exhaustive]`.
- MessagePack serializes structs as maps with field names.
- `said::saidify` computes SAIDs in JSON, CBOR and MessagePack into one or
  more fields; `make_me_happy` and `make_me_sad` use it and return an error
  when the SAID field is missing.
- The `SAD` derive, the `sad_macros` crate and the `macros` feature are
  removed. `said::saidify_value(&mut value, code, format, labels)` computes
  the SAID of any type that serializes as a map: replace `#[said]` by
  naming the fields in `labels` (`&["d"]`, or `&["i", "d"]`), and
  `#[version(..)]` by a field `v: SerializationInfo` set with
  `SerializationInfo::new_empty`. SAID fields must be serialized while
  empty, so no `skip_serializing_if` on them. The SAIDs are the same as the
  derive's.
- `said::verify(message, format, labels)` checks the SAID of a received
  message from its bytes; use it in place of `SAD::derivation_data` and
  `verify_binding` on a deserialized struct.
- The `SAD` trait stays for types that compute their SAID themselves;
  `SAD::compute_digest` returns `Result<(), Error>` and
  `SAD::derivation_data` returns `Result<Vec<u8>, Error>`.
- `version::error::Error` is `#[non_exhaustive]` and has an `InvalidSaid`
  variant.
- `version::error::Error::Disconnect` is `ParseInt`.
- `HashFunction::digest_from_stream` and `derive_from_stream` are available
  without the `file` feature, for every digest code.
