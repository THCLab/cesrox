#!/usr/bin/env bash
# Regenerate test-vectors/v2 from the keripy revision pinned in requirements.txt.
# Requires uv and libsodium (needed by keripy).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
venv="${VENV:-$here/.venv}"
rev="$(sed -n 's/^keri @ git+.*@\([0-9a-f]\{40\}\)$/\1/p' "$here/requirements.txt")"

if [ ! -x "$venv/bin/python" ]; then
    uv venv --quiet --python 3.14 "$venv"
fi
uv pip install --quiet --python "$venv/bin/python" -r "$here/requirements.txt"

rm -rf "$here/../v2"
cd "$here"
"$venv/bin/python" -I -W ignore gen_vectors.py "$here/.." --keripy-rev "$rev" >/dev/null
echo "vectors written to $(cd "$here/.." && pwd)/v2 (keripy $rev)"
