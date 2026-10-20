#!/usr/bin/env bash
# Regenerate the keripy vectors in test-vectors/v2/keripy from the revision
# pinned in requirements.txt. Requires uv and libsodium.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
venv="${VENV:-$here/.venv}"
rev="$(sed -n 's/^keri @ git+.*@\([0-9a-f]\{40\}\)$/\1/p' "$here/requirements.txt")"

if [ ! -x "$venv/bin/python" ]; then
    uv venv --quiet --python 3.14 "$venv"
fi
uv pip install --quiet --python "$venv/bin/python" -r "$here/requirements.txt"

out="$here/../../v2/keripy"
rm -rf "$out"
cd "$here"
"$venv/bin/python" -I -W ignore gen_vectors.py "$out" --keripy-rev "$rev" >/dev/null
echo "vectors written to $(cd "$out" && pwd) (keripy $rev)"
