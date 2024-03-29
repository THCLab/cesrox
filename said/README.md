# Self-Addressing Identifier

A Rust implementation of the [IETF Draft SAID specification](https://weboftrust.github.io/ietf-said/draft-ssmith-said.html).

Self-Addressing Identifier (SAID) provides a compact text representation of digests of data. It supports multiple hash algorithms (see below).

## License

EUPL 1.2 

We have distilled the most crucial license specifics to make your adoption seamless: [see here for details](https://github.com/THCLab/licensing).

## Example
```rust
let data = "hello there";
let code: HashFunction = HashFunctionCode::Blake3_256.into();
let sai = code.derive(data.as_bytes());

assert_eq!(format!("{}", sai), "ENmwqnqVxonf_bNZ0hMipOJJY25dxlC8eSY5BbyMCfLJ");
assert!(sai.verify_binding(data.as_bytes()));
assert!(!sai.verify_binding("wrong data".as_bytes()));
```

See https://github.com/THCLab/cesrox/blob/master/said/tests/ for full fledged examples.

#### Supported hash functions

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


## Self Addressing Data

Module `sad` provides trait `SAD` that has functions:
- `compute_digest` - computes the Self Addressing Identifier of a data structure, places it in a chosen field,
- `derivation_data` - returns data that are used for SAID computation.

The SAD trait can be implemented for structures using the provided derive macro. It allows users to select which fields will be replaced by the computed Self Addressing Identifier.
To use macro, feature `macros` need to be enabled. It works only for structures that implement `Serialize` using the `#[derive(Serialize)]` attribute, rather than a custom implementation.
### Attributes

Macro uses with following attributes:
- `version` - adds version field while computing derivation data. Version string contains compact representation of field map, serialization format, and size of a serialized message body. Attribute let user specify protocol code and its major and minor version. When attribute is used, the structure automatically implements the `Encode` trait, which provides the `encode` function for serializing the element according to the chosen serialization format.
- `said` -  this attribute allows users to choose the hash function for computing Self Addressing Identifier and serialization format. The hash function can be specified using the derivation code from the table above. The available serialization formats are JSON, CBOR, and MGPK. By default, JSON and Blake3-256 are used.

#### Field attributes:
- `said` - marks field that should be replaced by computed digest during `compute_digest`.

### Example:
```rust
#[derive(SAD, Serialize)]
#[version(protocol = "KERI", major = 1, minor = 0)]
struct Something {
	pub text: String,
	#[said]
	pub d: Option<SelfAddressingIdentifier>,
}
```

## Releasing new version
[cargo-release](https://github.com/crate-ci/cargo-release) is required

To release new version run `cargo release`

Due to [release config](./release.toml) it will bump version, create new git tag
and push it to remote.
