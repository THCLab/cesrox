# CESRox

Rust implementations of [CESR](https://trustoverip.github.io/kswg-cesr-specification/),
the Composable Event Streaming Representation, and of self-addressing
identifiers.

| Crate | What it is |
|---|---|
| [cesrox](cesr) | Encoding and parsing of CESR V2 streams, text and binary |
| [said](said) | Self-addressing identifiers and self-addressing data |
| [sad_macros](said/sad_macros) | The `SAD` derive used by `said` |
| [cesr-migrate](cesr-migrate) | Converts CESR stored by cesrox before 2.0 to CESR V2 |

Both libraries are tested against shared CESR V2 test vectors from several
sources, see [test-vectors](test-vectors/README.md). Upgrading from an
earlier version is described in [MIGRATING.md](MIGRATING.md).

## License

EUPL 1.2

We have distilled the most crucial license specifics to make your adoption seamless: [see here for details](https://github.com/THCLab/licensing).

## Releasing

[cargo-release](https://github.com/crate-ci/cargo-release) is required. Run
`cargo release <level> --workspace`; the [release config](release.toml)
bumps versions, commits, tags and pushes, and the tag workflows publish the
crates.
