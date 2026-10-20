# said

Self-addressing identifiers (SAIDs) for Rust: digests of data that are
embedded in that data, as specified in the
[CESR specification](https://trustoverip.github.io/kswg-cesr-specification/)
and used by KERI and ACDC.

## License

EUPL 1.2

We have distilled the most crucial license specifics to make your adoption seamless: [see here for details](https://github.com/THCLab/licensing).

## Digests

```rust
use said::derivation::{HashFunction, HashFunctionCode};

let data = "hello there";
let code: HashFunction = HashFunctionCode::Blake3_256.into();
let sai = code.derive(data.as_bytes());

assert_eq!(sai.to_string(), "ENmwqnqVxonf_bNZ0hMipOJJY25dxlC8eSY5BbyMCfLJ");
assert!(sai.verify_binding(data.as_bytes()));
assert!(!sai.verify_binding("wrong data".as_bytes()));
```

Large inputs can be hashed from any `std::io::Read` with
`HashFunction::derive_from_stream`.

| Code | Digest | SAID length |
|------|--------|-------------|
| `E`  | Blake3-256  | 44 |
| `F`  | Blake2b-256 | 44 |
| `G`  | Blake2s-256 | 44 |
| `H`  | SHA3-256    | 44 |
| `I`  | SHA2-256    | 44 |
| `0D` | Blake3-512  | 88 |
| `0E` | Blake2b-512 | 88 |
| `0F` | SHA3-512    | 88 |
| `0G` | SHA2-512    | 88 |

## Self-addressing data

`said::saidify` computes the SAID of a map serialized as JSON, CBOR or
MessagePack and writes it into the map's SAID fields: usually `d`, or `d`
and `i` when an identifier is its own SAID. If the map has a version string
in `v`, its serialization kind and size are filled in.

```rust
use said::{derivation::HashFunctionCode, sad::SerializationFormats, saidify, Sad};

let mut sad: Sad =
    serde_json::from_str(r#"{"v":"KERICAACAAJSONAAAA.","d":"","text":"Hello"}"#).unwrap();
let (said, cbor) = saidify(
    &mut sad,
    HashFunctionCode::Blake3_256,
    SerializationFormats::CBOR,
    &["d"],
)
.unwrap();
```

Version strings are read and written in both forms: `KERI10JSON00014b_`
for protocol version 1 and `KERICAACAAJSONAABk.` for version 2 and later.

### The SAD derive

With the `macros` feature, `#[derive(SAD)]` implements the `SAD` trait for
a struct that also derives `serde::Serialize`:

- `#[said]` marks fields that receive the SAID; they are typically
  `Option<SelfAddressingIdentifier>`.
- `#[version(protocol = "KERI", major = 2, minor = 0)]` on the struct adds a
  version string `v` as the first field of the serialized message and
  implements `said::version::Encode`, which serializes the complete message.

```rust
use said::{derivation::HashFunctionCode, sad::{SerializationFormats, SAD}, version::Encode};

#[derive(said::sad::SAD, serde::Serialize, Clone)]
#[version(protocol = "KERI", major = 2, minor = 0)]
struct Event {
    text: String,
    #[said]
    d: Option<said::SelfAddressingIdentifier>,
}

let mut event = Event { text: "Hello".into(), d: None };
let code = HashFunctionCode::Blake3_256;
event.compute_digest(&code, &SerializationFormats::JSON)?;
let message = event.encode(&code, &SerializationFormats::JSON)?;
```

## The `sai` tool

With the `file` feature, the `sai` binary computes and verifies SAIDs:

```sh
sai gen -t E -d "hello there"        # or -f FILE
sai verify -s ENmwqnqVxonf_bNZ0hMipOJJY25dxlC8eSY5BbyMCfLJ -d "hello there"
```

`verify` exits with a failing status when the SAID does not match.
