# Version

The library that encapsulates logic for building version string, described in [KERI](https://weboftrust.github.io/ietf-keri/draft-ssmith-keri.html#name-version-string-field) and [ACDC](https://trustoverip.github.io/tswg-acdc-specification/draft-ssmith-acdc.html#section-2.3) documentation. It is compact representation of field map, serialization format, and size of a serialized message body. The resulting version string can be used by a parser to extract the full serialization message body from a stream without first deserializing it or parsing it field-by-field.

Version string has the following form: `[FIELD_MAP]vvSSSShhhhhh_`, where:

- `[FIELD_MAP]`- string of uppercase letters of any length that indicates the enclosing field map serialization, for example `KERI`, `ACDC`.
- `vv`- provides the major and minor version numbers of used field map serialization, first `v` for major and second for minor. They are represented in lowercase hexadecimal notation.
- `SSSS`- indicates the serialization type in uppercase. The supported serialization types are JSON, CBOR, and MGPK.
- `hhhhhh`- provides the total number of characters in the message body in lowercase hexadecimal notation.

For usage examples checkout `tests` folder.