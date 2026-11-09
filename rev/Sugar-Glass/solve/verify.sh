#!/usr/bin/env bash
# Sugar Glass (SecLeaf CTF 2026): feed the recovered flag to the ORIGINAL binary.
# The checker is a Linux x86-64 ELF that reads one line from stdin. On any other host
# the script re-runs itself in a throwaway linux/amd64 container with no network.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATT="$HERE/../attachments"
BIN="sugar_glass"
WRONG='SecLeaf{this_is_not_the_flag_xx}'

if [[ "$(uname -s)/$(uname -m)" != "Linux/x86_64" ]]; then
    command -v docker >/dev/null || { echo "Need Linux x86-64 or Docker" >&2; exit 1; }
    exec docker run --rm --platform linux/amd64 --network none \
        -v "$(cd "$HERE/.." && pwd):/c" -w /c/solve debian:stable-slim bash verify.sh
fi

FLAG="$(python3 "$HERE/solve.py" | sed -n 's/^\[+\] FLAG: //p')"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
cp "$ATT/$BIN" "$work/" && chmod +x "$work/$BIN"

printf '[*] wrong flag  -> '; printf '%s\n' "$WRONG" | "$work/$BIN" || true
printf '[*] real flag   -> '; printf '%s\n' "$FLAG"  | "$work/$BIN"     # expected: Filed.
echo "[+] FLAG: $FLAG"
