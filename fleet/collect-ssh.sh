#!/usr/bin/env bash
# SSH-based fleet collection (fallback when SSM is unavailable).
# Deploys al2023-preflight to each host, runs a JSON scan, pulls the report back.
#
# Usage: ./fleet/collect-ssh.sh <output-dir> <host1> [host2 ...]
set -euo pipefail

OUTDIR="${1:?usage: collect-ssh.sh <output-dir> <host...>}"; shift
[ $# -ge 1 ] || { echo "usage: collect-ssh.sh <output-dir> <host...>" >&2; exit 2; }

PROTO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TARBALL=$(mktemp /tmp/al2023-preflight.XXXX.tar.gz)
trap 'rm -f "$TARBALL"' EXIT
tar czf "$TARBALL" -C "$PROTO_DIR" al2023_preflight
mkdir -p "$OUTDIR"

ok=0; fail=0
for host in "$@"; do
    echo "== $host"
    if scp -q -o ConnectTimeout=8 "$TARBALL" "ec2-user@$host:/tmp/al2023-preflight.tar.gz" \
       && ssh -o ConnectTimeout=8 "ec2-user@$host" '
            set -e
            WORK=$(mktemp -d)
            tar xzf /tmp/al2023-preflight.tar.gz -C "$WORK"
            cd "$WORK"
            sudo python3 -m al2023_preflight.cli scan --json --output "$WORK/out" >/dev/null 2>&1 || true
            test -n "$(ls "$WORK"/out/*.json 2>/dev/null)"
            sudo cat "$WORK"/out/*.json
            sudo rm -rf "$WORK" /tmp/al2023-preflight.tar.gz
       ' > "$OUTDIR/.$host.json.tmp"; then
        # name the file from the report itself ({hostname}-report_{date}.json)
        name=$(python3 -c "
import json,sys
d=json.load(open('$OUTDIR/.$host.json.tmp'))
print('%s-report_%s.json' % (d['hostname'], d['scanned_at'].split('T')[0]))")
        mv "$OUTDIR/.$host.json.tmp" "$OUTDIR/$name"
        echo "   -> $name"
        ok=$((ok+1))
    else
        rm -f "$OUTDIR/.$host.json.tmp"
        echo "   FAILED (unreachable or scan error)"
        fail=$((fail+1))
    fi
done
echo
echo "collected: $ok, failed: $fail -> $OUTDIR"
