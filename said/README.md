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
- `compute_digest` - computes the Self Addressing Identifier of a data structure, places it in a chosen field, and returns `Self` with the updated field,
- `derivation_data` - returns data that are used for SAID computation.

Following variant attributes are provided: 
- `version` - adds version string field while computing derivation data. It contains compact representation of field map, serialization format, and size of a serialized message body. Attribute let user specify protocol code, its major and minor version and format of serialized data (one of "json", "cbor", "mgpk")
- `said` - marks field that should be replaced by computed digest during `compute_digest`.

### Example:
```rust
#[derive(SAD, Serialize)]
#[version(protocol = "KERI", major = 1, minor = 0, format = "json")]
struct VersionSomething {
	pub text: String,
	#[said]
	pub d: Option<SelfAddressingIdentifier>,
}
```

Derive macro can be used for implementing `SAD` trait for structures. It allows the user to choose which fields will be replaced by the computed Self Addressing Identifier.
To use macro, feature `macros` need to be enabled. It works only for structures that implements `Serialize` using `#[derive(Serialize)]` instead of custom implementation.



## Releasing new version
[cargo-release](https://github.com/crate-ci/cargo-release) is required

To release new version run `cargo release`

Due to [release config](./release.toml) it will bump version, create new git tag
and push it to remote.
