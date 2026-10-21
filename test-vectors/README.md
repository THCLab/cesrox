# CESR V2 test vectors

Language-neutral test vectors for CESR V2. `cesrox` and `said` run all of
them in their `vectors` integration tests, and other implementations can
consume the JSON files directly.

Vectors are collected from several sources so that implementations are
aligned with each other rather than with any single one. Each source has its
own directory of data and, where the vectors are generated, a generator:

```
harness.rs                shared Rust runner used by both crates' tests
sources/<source>/         how a source's vectors are produced
v2/<source>/
  manifest.json           source, revision, generator version, vector counts
  primitives/             fixed-size and variable-length primitives, special values
  indexed/                indexed signatures with edge index/ondex values
  counters/               every V2 counter with edge counts and big forms
  groups/                 attachment and seal groups built from primitives, with
                          their binary (qb2) form
  streams/                whole messages with attachments (JSON, CBOR, MGPK, CESR),
                          text- and binary-domain groups
  kels/                   key event logs and the events of each the source accepted
                          from them, including events it must reject
  said/                   digests, saidified maps and messages, version strings
  legacy/                 streams in the format of cesrox before 2.0 and their V2 form
  negative/negative.json  input the source rejects; implementations must reject it
  negative/edge.json      odd input the source accepts; recorded for review
```

A source may provide any subset of these files. Every file has the shape
`{"schema": "<kind>/1", "generator": {...}, "vectors": [{"id": ...}, ...]}`.
Vector ids are unique within a source and stable across regenerations; the
tests prefix them with the source name.

Current sources:

| Source | Produced by | Pinned at |
|---|---|---|
| `cesrox` | `sources/cesrox/generate.sh`, see `sources/cesrox/README.md` | the commit that contains them |
| `keripy` | `sources/keripy/generate.sh` | `sources/keripy/requirements.txt` |
| `spec` | examples copied from the CESR specification, see `sources/spec/README.md` | specification commit in the manifest |

## Regenerating

A generated source is rebuilt with its script, for example:

```sh
test-vectors/sources/keripy/generate.sh   # needs uv and libsodium
```

Generation is deterministic: the same pinned revision always produces
identical files. CI regenerates every generated source and fails if the
result differs from the committed files.

## Confirming a source with another implementation

Vectors that one implementation writes are confirmed by another before they
are relied on. `sources/keripy/check.sh` reads the vectors of every source
other than keripy with the pinned keripy and compares the outcome with
`sources/keripy/cross_check/<source>.txt`, the list of vectors keripy does
not confirm and why. CI runs it; after an intentional change rewrite the
lists with `check.sh --bless`.

## Adding a source

Put the vectors under `v2/<source>/` in the layout above and, if they are
generated, the generator under `sources/<source>/`. The tests pick the new
directory up automatically; record its known failures as described below.

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

The CESR specification is authoritative. Where a source and the
specification disagree, the specification wins: such vectors are corrected
in the source's generator or listed as expected failures with the reason.
