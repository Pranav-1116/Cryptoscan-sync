#!/bin/sh
# Weekly evidence-chain checkpoint choreography (cryptoscan-evidence-checkpoint.service).
#
# For each evidence stream (network, runtime):
#   1. verify     — last week's archived checkpoint still signs under the key
#   2. continuity — the live chain still CONTAINS what that checkpoint anchored
#   3. sign       — this week's checkpoint, written to a side file first
#   4. verify     — the fresh checkpoint before it is promoted
#
# Any failure preserves the previous checkpoint and exits non-zero (the unit
# fails; hook alerting to unit failures). The files are proof documents —
# archive them per docs/runbooks/evidence-checkpoint-archive.md.
#
# First run (no previous checkpoint) skips steps 1-2 and signs the first
# anchor. Exit codes follow the CLI: 1 = invalid/rewritten, 2 = cannot prove.
set -u

DIR="${CHECKPOINT_DIR:-/var/lib/cryptoscan/checkpoints}"
PY="${PYTHON:-python3}"

mkdir -p "$DIR" || exit 2
status=0

for stream in network runtime; do
  prev="$DIR/evidence-checkpoint-$stream.json"
  next="$DIR/evidence-checkpoint-$stream.next.json"
  if [ -f "$prev" ]; then
    "$PY" scripts/evidence_checkpoint.py verify --file "$prev" || status=1
    "$PY" scripts/evidence_checkpoint.py continuity --stream "$stream" --file "$prev" || status=1
  fi
  "$PY" scripts/evidence_checkpoint.py sign --stream "$stream" --file "$next" || status=1
  "$PY" scripts/evidence_checkpoint.py verify --file "$next" || status=1
done

if [ "$status" -ne 0 ]; then
  echo "checkpoint run FAILED — previous checkpoints preserved; see docs/runbooks/evidence-checkpoint-archive.md" >&2
  exit "$status"
fi

for stream in network runtime; do
  mv "$DIR/evidence-checkpoint-$stream.next.json" "$DIR/evidence-checkpoint-$stream.json"
done
echo "checkpoints signed and verified for streams: network runtime"
