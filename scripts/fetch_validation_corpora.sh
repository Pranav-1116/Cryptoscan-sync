#!/usr/bin/env bash
# Fetch the third-party corpora used for external accuracy validation.
#
#   scripts/fetch_validation_corpora.sh [dest]        # default: /tmp/extval
#
# External validation only means something if the code was written by somebody
# else and never used to tune the scanner. These are public, crypto-dense
# upstreams chosen so that each of the bank languages has both a recall target
# (a real crypto library) and a precision target (files with no crypto at all,
# which every one of these repos also contains in bulk).
#
# Python and Go need no download: the project venv and the Go module cache are
# already third-party trees. Point scan_third_party.py at them directly:
#
#   python scripts/scan_third_party.py .venv/lib/python3*/site-packages/pip
#   python scripts/scan_third_party.py "${GOPATH:-$HOME/go}/pkg/mod/golang.org"
#
# Nothing here is committed, and nothing is executed — the scanner only reads.
set -euo pipefail

DEST="${1:-/tmp/extval}"
mkdir -p "$DEST"

# repo                      language  why
REPOS=(
  "bcgit/bc-java            java      BouncyCastle Java — every primitive, plus a large non-crypto ASN.1/util body"
  "apache/commons-codec     java      digests and HMAC beside Base64/Soundex/binary, which must stay silent"
  "bcgit/bc-csharp          csharp    BouncyCastle .NET — the C# counterpart of bc-java"
)

for entry in "${REPOS[@]}"; do
  read -r repo lang _desc <<<"$entry"
  name="$(basename "$repo")"
  if [ -d "$DEST/$name" ]; then
    echo "have    $name ($lang)"
    continue
  fi
  echo "cloning $name ($lang)"
  git clone --depth 1 -q "https://github.com/$repo.git" "$DEST/$name"
done

echo
echo "corpus sizes:"
for d in "$DEST"/*/; do
  printf '  %-18s java=%-6s cs=%-6s go=%s\n' "$(basename "$d")" \
    "$(find "$d" -name '*.java' | wc -l)" \
    "$(find "$d" -name '*.cs'   | wc -l)" \
    "$(find "$d" -name '*.go'   | wc -l)"
done

cat <<EOF

now scan each one and review the findings by hand:
  python scripts/scan_third_party.py $DEST/bc-java
  python scripts/scan_third_party.py $DEST/bc-csharp v | less

a CRASH line is the finding that matters most: a parser that dies on a file
skips it silently, so it is a recall hole that no corpus test would catch.
EOF
