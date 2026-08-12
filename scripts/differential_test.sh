#!/usr/bin/env bash
# Differential verification: run AWSHound (the Python oracle) and awshound (Go)
# on the same GAAD fixtures and assert the emitted OpenGraph graphs are
# semantically identical — same node id->kinds and same (start,end,kind) edge
# triples. Any divergence is a porting bug in the Go rewrite.
#
# Covers the IAM path end-to-end: collectors→store→evaluator→nodes+edges→emit.
# Non-IAM services (S3/KMS/EC2/Lambda/CFN/EKS/SSM/Organizations) are exercised by
# the live integration suite, which has real infra for them.
#
# Usage: scripts/differential_test.sh          (exit 0 = all match)
set -euo pipefail

AWSHOUND="${AWSHOUND:-/workspace/AWSHound}"
export PATH="$PATH:/usr/local/go/bin"

repo="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
bin="$work/awshound"
go -C "$repo" build -o "$bin" ./cmd/awshound

cat > "$work/diff.py" <<'PY'
import json, sys
def load(p):
    d = json.load(open(p)); g = d.get('graph', d)
    return ({n['id']: frozenset(n.get('kinds', [])) for n in g['nodes']},
            set((e['start']['value'], e['end']['value'], e['kind']) for e in g['edges']))
pn, pe = load(sys.argv[1]); gn, ge = load(sys.argv[2])
nm, nx = set(pn) - set(gn), set(gn) - set(pn)
kd = [i for i in set(pn) & set(gn) if pn[i] != gn[i]]
em, ex = pe - ge, ge - pe
ok = not (nm or nx or kd or em or ex)
print("  nodes %d/%d  edges %d/%d%s" % (
    len(set(pn) & set(gn)), len(pn), len(pe & ge), len(pe),
    "" if ok else "  | node-miss=%d node-extra=%d kind-diff=%d edge-miss=%d edge-extra=%d" % (
        len(nm), len(nx), len(kd), len(em), len(ex))))
for e in sorted(em)[:8]: print("     MISSING", e)
for e in sorted(ex)[:8]: print("     EXTRA  ", e)
sys.exit(0 if ok else 1)
PY

fails=0
shopt -s nullglob
for fx in "$AWSHOUND"/tests/fixtures/sample_auth_details.json "$AWSHOUND"/tests/fixtures/s3/account*_gaad.json; do
  name="$(basename "$fx")"
  if ! "$AWSHOUND"/.venv/bin/python -m awshound --gaad "$fx" -o "$work/py.json" \
        --s3-filter "$AWSHOUND"/configs/s3-filter.default.json >/dev/null 2>&1; then
    echo "SKIP $name (python oracle failed)"; continue
  fi
  "$bin" --gaad "$fx" -o "$work/go.json" >/dev/null 2>&1
  if python3 "$work/diff.py" "$work/py.json" "$work/go.json"; then
    echo "PASS $name"
  else
    echo "FAIL $name"; fails=$((fails + 1))
  fi
done

echo "differential: $fails divergence(s)"
exit "$fails"
