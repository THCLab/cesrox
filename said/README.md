# Self-Addressing Identifier

A Rust implementation of the [IETF Draft SAID specification](https://weboftrust.github.io/ietf-said/draft-ssmith-said.html).

Self-Addressing Identifier (SAI) provides a compact text representation of digests of data.
It supports multiple hash algorithms.

Self Addressing Identifier is base64 encoded hash of data, prepended with
one or two letter prefix, called derivation code. Derivation code determines
which hash algorithm was used to derive the digest.

| derivation code| digest type 		| code length 	| identifier length	|
|---------------|-------------------|---------------|-------------------|
| E				| Blake3-256 Digest | 1				| 44 				|
| F 			| Blake2b-256 Digest| 1				| 44				|
| G				| Blake2s-256 Digest| 1				| 44				|
| H				| SHA3-256 Digest 	| 1				| 44				|
| I				| SHA2-256 Digest	| 1				| 44				|
| 0D			| Blake3-512 Digest | 2				| 88				|
| 0E			| Blake2b-512 Digest| 2				| 88				|
| 0F			| SHA3-512 Digest 	| 2				| 88				|
| 0G			| SHA2-512 Digest	| 2				| 88				|

## License

EUPL 1.2 

We have distilled the most crucial license specifics to make your adoption seamless: [see here for details](https://github.com/THCLab/licensing).

## Usage

To derive Self Addressing Identifier, `HashFunctionCode` enum can be used. It
determines hashing algorithm used for Identifier derivation. Here are its
possible values:

```rust
pub enum HashFunctionCode {
    Blake3_256,
    Blake2B256(Vec<u8>),
    Blake2S256(Vec<u8>),
    SHA3_256,
    SHA2_256,
    Blake3_512,
    SHA3_512,
    Blake2B512,
    SHA2_512,
}
```

`verify_bindings` function checks if provided data matches digest encoded in Self Addressing Identifier.

### Example
```rust
let data = "hello there";
let code: HashFunction = HashFunctionCode::Blake3_256.into();
let sai = code.derive(data.as_bytes());

assert_eq!(format!("{}", sai), "ENmwqnqVxonf_bNZ0hMipOJJY25dxlC8eSY5BbyMCfLJ");
assert!(sai.verify_binding(data.as_bytes()));
assert!(!sai.verify_binding("wrong data".as_bytes()));
```

## Self Addressing Data

Module `sad` provides trait `SAD` that has function:
- `compute_digest` - computes the Self Addressing Identifier of a data structure, places it in a chosen field, and returns `Self` with the updated field,
- `derivation_data` - returns data that are used for SAID computation.

Derive macro can be used for implementing `SAD` trait for structures. It allows the user to choose which fields will be replaced by the computed Self Addressing Identifier.
### Example
Here's an example of defining structure `Something` that is `SAD` and keeps the SAID of itself in a `d` field:

```rust
    use sad_macros::SAD;
    use said::sad::SAD;

    #[derive(SAD, Serialize)]
    struct Something {
        pub text: String,
        #[said]
        pub d: Option<SelfAddressingIdentifier>,
    }

    let something = Something {
        text: "Hello world".to_string(),
        d: None,
    };

    let saided_something =
        something.compute_digest(HashFunctionCode::Blake3_256, SerializationFormats::JSON);
    let computed_digest = saided_something.d.as_ref();
    let derivation_data =
        saided_something.derivation_data(&HashFunctionCode::Blake3_256, &SerializationFormats::JSON);
    let saided = serde_json::to_string(&saided_something).unwrap();

    assert_eq!(
        format!(
            r#"{{"text":"Hello world","d":"{}"}}"#,
            "############################################"
        ),
       derivation_data 
    );
    assert_eq!(
        r#"{"text":"Hello world","d":"EF-7wdNGXqgO4aoVxRpdWELCx_MkMMjx7aKg9sqzjKwI"}"#,
        saided
    );
```
For more examples, please refer to the `said/tests/sad_tests.rs` file.

## Releasing new version
[cargo-release](https://github.com/crate-ci/cargo-release) is required

To release new version run `cargo release`

Due to [release config](./release.toml) it will bump version, create new git tag
and push it to remote.
