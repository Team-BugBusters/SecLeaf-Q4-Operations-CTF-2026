#!/usr/bin/env bash
# Blackout-Protocol (SecLeaf CTF 2026): check the recovered flag against the ORIGINAL verifier.
# The verifier is a Linux x86-64 ELF that reads its data files from the current
# directory, so it runs from ../attachments/. On any other host (e.g. macOS) the
# script re-runs itself in a throwaway linux/amd64 container with no network.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATT="$HERE/../attachments"
BIN="blackout_protocol"
FLAG='SecLeaf{n01s3_1n_th3_w1r35_4nd_4ft3r1m4g3s!!!!!}'
WRONG='SecLeaf{this_is_not_the_flag}'

if [[ "$(uname -s)/$(uname -m)" != "Linux/x86_64" ]]; then
    command -v docker >/dev/null || { echo "Need Linux x86-64 or Docker" >&2; exit 1; }
    exec docker run --rm --platform linux/amd64 --network none \
        -v "$(cd "$HERE/.." && pwd):/c" -w /c/solve debian:stable-slim bash verify.sh
fi

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
cp "$ATT"/* "$work"/ && cd "$work" && chmod +x "$BIN"

printf '[*] wrong flag  -> '; ./"$BIN" "$WRONG" || true
printf '[*] real flag   -> '; ./"$BIN" "$FLAG"     # expected: Authenticated. (exit 0)
echo "[+] FLAG: $FLAG"
