# Vectors written by cesrox and said

`generate.sh` runs this crate, which builds every vector with cesrox and
said and writes them to `test-vectors/v2/cesrox`. They are committed with
the code that writes them; CI regenerates them and fails if the code and
the files disagree.

They cover what the other sources have little of:

| File | Contents |
|---|---|
| `streams/messages.json` | signed messages in JSON, CBOR and MessagePack with attachments in `-C`, text and binary domain, a key event log, mixed domains, a genus code, `-X`/`-Y`/`-T`/`-O` groups, an enclosed body (`-H`), a native field map, big counters |
| `groups/groups.json` | groups with small and big index codes, current-only and dual indexes, big counts and sequence numbers |
| `said/saidify.json` | SAIDs in every format, of messages that are their own identifier (`d` and `i`), with V1 and V2 version strings, nested maps, every digest code |
| `legacy/migrate.json` | streams in the format of cesrox before 2.0 and their V2 form |
| `negative/negative.json` | input that must be rejected: non-canonical primitives, wrong group counts, malformed version strings, messages whose SAID does not bind |

Keys and filler bytes are derived from fixed labels, so the output is the
same on every run. Signatures are Ed25519 signatures over the message
bodies by the keys listed in `sigs_verkeys`; signatures in `-X` and `-Y`
groups are by other keys.

Nothing the specification leaves open is written here: indexed P-256
signature codes and the `-N` counter are left out.

## Confirmed by a second implementation

Vectors written by an implementation only show what that implementation
does. Before others rely on them, `sources/keripy/check.sh` reads every
vector with keripy: it walks streams and groups primitive by primitive in
both domains, loads message bodies, which checks their SAIDs, verifies the
signatures, recomputes SAIDs and checks that negative input is rejected.
Vectors keripy does not confirm are listed with the reason in
`sources/keripy/cross_check/cesrox.txt`; CI fails when that list changes.
