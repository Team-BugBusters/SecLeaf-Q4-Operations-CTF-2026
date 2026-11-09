#!/usr/bin/env bash
# Null-Choir (SecLeaf CTF 2026): check the recovered flag against the ORIGINAL verifier.
# The verifier is a Linux x86-64 ELF that reads its data files from the current
# directory, so it runs from ../attachments/. On any other host (e.g. macOS) the
# script re-runs itself in a throwaway linux/amd64 container with no network.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATT="$HERE/../attachments"
BIN="null_choir"
FLAG='SecLeaf{th3_ch01r_s1ng5_1n_5h4d0w_m4ch1n35!!!!!}'
WRONG='SecLeaf{this_is_not_the_flag}'

if [[ "$(uname -s)/$(uname -m)" != "Linux/x86_64" ]]; then
    command -v docker >/dev/null || { echo "Need Linux x86-64 or Docker" >&2; exit 1; }
    exec docker run --rm --platform linux/amd64 --network none \
        -v "$(cd "$HERE/.." && pwd):/c" -w /c/solve debian:stable-slim bash verify.sh
fi

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
cp "$ATT"/* "$work"/ && cd "$work" && chmod +x "$BIN"

printf '[*] wrong flag  -> '; ./"$BIN" "$WRONG" || true
printf '[*] real flag   -> '; ./"$BIN" "$FLAG"     # expected: Harmony. (exit 0)
echo "[+] FLAG: $FLAG"
