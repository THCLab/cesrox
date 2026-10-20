# CESR V2 test vectors

Language-neutral test vectors for CESR V2, generated with
[keripy](https://github.com/WebOfTrust/keripy) as the reference
implementation. `cesrox` and `said` run them in their `vectors` integration
tests. Other CESR implementations can consume the JSON files directly.

The keripy revision is pinned in `gen/requirements.txt` and recorded in
`v2/manifest.json` and in each file's `generator` field.

## Layout

```
gen/                      generator (gen_vectors.py), pinned keripy, generate.sh
harness.rs                shared Rust runner used by both crates' tests
v2/
  manifest.json           generator version, keripy revision, vector counts
  primitives/fixed.json   every fixed-size Matter code (random, all-zero, all-0xff raw)
  primitives/variable.json  variable-length codes for several raw lengths, big promotion
  primitives/special.json Tags, DateTime, Number, Texter, Bexter, Pather, Labeler, Verser, ...
  indexed/indexers.json   every indexed signature code with edge index/ondex values
  counters/counters.json  every V2 counter with edge counts, big promotion, genus codes
  streams/messages.json   whole keripy V2 messages with attachments (JSON, CBOR, MGPK, CESR)
  said/digests.json       every digest code on fixed inputs
  said/saidify.json       saidified maps (plain and versioned) and complete messages
  said/version_strings.json  V2 version strings
  negative/negative.json  input keripy rejects; implementations must reject it
  negative/keripy_accepts_edge.json  odd input keripy accepts; recorded for review
```

Every file has the shape
`{"schema": "<kind>/1", "generator": {...}, "vectors": [{"id": ...}, ...]}`.
Vector ids are unique within a file and stable across regenerations.

## Regenerating

Requires [uv](https://docs.astral.sh/uv/) and libsodium (used by keripy):

```sh
test-vectors/gen/generate.sh
```

The output is deterministic: raw material is derived from fixed labels, so
the same keripy revision always produces identical files. CI regenerates the
vectors and fails if they differ from the committed ones.

To move to a newer keripy, change the revision in `gen/requirements.txt`,
regenerate, review the diff and update the expected-failure lists below.

## Expected failures

The crates do not yet pass every vector. Known failures are listed in
`cesr/tests/vectors_expected_failures.txt` and
`said/tests/vectors_expected_failures.txt`. The `vectors` test fails when a
vector fails that is not listed, and also when a listed vector starts
passing, so the lists only shrink. After an intentional change, rewrite them
with:

```sh
CESR_VECTORS_BLESS=1 cargo test --workspace --test vectors
```

keripy is the reference implementation, not the specification. Where keripy
and the CESR specification disagree, the specification wins; such vectors
should be corrected in the generator with a note explaining the deviation.
