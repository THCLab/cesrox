#!/usr/bin/env bash
# Read the vectors of every other source with the pinned keripy and compare
# the outcome with cross_check/<source>.txt. Pass --bless to rewrite those
# lists after an intentional change. Requires uv and libsodium.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
venv="${VENV:-$here/.venv}"

if [ ! -x "$venv/bin/python" ]; then
    uv venv --quiet --python 3.14 "$venv"
fi
uv pip install --quiet --python "$venv/bin/python" -r "$here/requirements.txt"

status=0
for dir in "$here"/../../v2/*/; do
    source="$(basename "$dir")"
    [ "$source" = keripy ] && continue
    "$venv/bin/python" -I -W ignore "$here/check.py" "$dir" \
        "$here/cross_check/$source.txt" "$@" || status=1
done
exit $status
