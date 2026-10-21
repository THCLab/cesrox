#!/usr/bin/env bash
# Regenerate the cesrox vectors in test-vectors/v2/cesrox from the code in
# this repository. Requires cargo.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="$here/../../v2/cesrox"
rm -rf "$out"
cargo run --quiet --manifest-path "$here/Cargo.toml" -- "$out"
echo "vectors written to $(cd "$out" && pwd)"
