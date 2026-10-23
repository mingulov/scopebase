#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# TT08 tail: local equivalent of .github/workflows/ci.yml.
#
# Runs the same causal selection and gates as CI, in one coordinator process:
# changed paths -> ChangeManifest -> select_affected (+ oracle agreement) ->
# gate resolution -> fast gates + affected profile gates + runnable cell gates
# -> RunAccounting -> retry-gate verdict over this run's outcome.
#
# No network (CARGO_NET_OFFLINE=1, every cargo invocation --offline), no
# secrets, no privileged operations. Heavy cargo work goes through
# bin/scopebase-build with an explicit absolute --lock-root. Cargo outputs
# land in a private run root (default target/tt08-local); nothing is installed
# and no shared manifest is edited.
#
# Exit codes: 0 full matrix attested; 1 usage/tool/gate failure; 3 incomplete
# with no failures (required checks unavailable or unexecuted).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CATALOG="$ROOT/profiles/cases-v1.json"
IMPACT="$ROOT/profiles/impact-v1.json"
RUN_ROOT="$ROOT/target/tt08-local"
LOCK_ROOT="${SCOPEBASE_LOCK_ROOT:-}"
CHANGED_FILE=""
CHANGED_FROM="HEAD"
FULL_RUN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --changed-file) CHANGED_FILE="$2"; shift 2;;
    --changed-from) CHANGED_FROM="$2"; shift 2;;
    --full) FULL_RUN=1; shift;;
    --run-root) RUN_ROOT="$2"; shift 2;;
    --lock-root) LOCK_ROOT="$2"; shift 2;;
    --catalog) CATALOG="$2"; shift 2;;
    --impact) IMPACT="$2"; shift 2;;
    -h|--help)
      echo "usage: ci_local.sh [--changed-file <txt> | --changed-from <range> | --full]"
      echo "                   [--run-root <dir>] --lock-root <abs-dir> [--catalog <json>] [--impact <json>]"
      exit 0;;
    *) echo "ci_local.sh: unknown argument $1" >&2; exit 1;;
  esac
done

case "$LOCK_ROOT" in
  /*) ;;
  *) echo "ci_local.sh: --lock-root must be an explicit absolute path" >&2; exit 1;;
esac

echo "TT08 tail local execution: root=$ROOT run_root=$RUN_ROOT lock_root=$LOCK_ROOT"
mkdir -p "$RUN_ROOT/logs"
export CARGO_TARGET_DIR="$RUN_ROOT/target"
export CARGO_NET_OFFLINE=1

SELECT_BIN="$CARGO_TARGET_DIR/debug/scopebase-select"
"$ROOT/bin/scopebase-build" --lock-root "$LOCK_ROOT" --resource build -- \
  cargo build --offline -p scopebase-testkit --bin scopebase-select
[ -x "$SELECT_BIN" ] || { echo "ci_local.sh: build did not produce $SELECT_BIN" >&2; exit 1; }

REQUESTED="$(python3 -c 'import json,sys; print(",".join(json.load(open(sys.argv[1]))["requested_profiles"]))' "$IMPACT")"

if [ "$FULL_RUN" -eq 1 ]; then
  python3 -c 'import json; json.dump({"changes":[{"type":"unknown","boundary":None,"reason":"scheduled full-matrix revalidation"}]}, open("'"$RUN_ROOT"'/manifest.json","w"), indent=1)'
  echo "manifest changes=1 (full revalidation)"
else
  if [ -n "$CHANGED_FILE" ]; then
    cp "$CHANGED_FILE" "$RUN_ROOT/changed.txt"
  else
    {
      git -C "$ROOT" diff --name-only "$CHANGED_FROM" -- . 2>/dev/null || true
      git -C "$ROOT" ls-files --others --exclude-standard -- . 2>/dev/null || true
    } | sort -u > "$RUN_ROOT/changed.txt"
  fi
  echo "changed paths: $(wc -l < "$RUN_ROOT/changed.txt")"
  "$SELECT_BIN" manifest --impact "$IMPACT" --changed "$RUN_ROOT/changed.txt" --out "$RUN_ROOT/manifest.json"
fi

"$SELECT_BIN" select --catalog "$CATALOG" --manifest "$RUN_ROOT/manifest.json" \
  --requested "$REQUESTED" --out "$RUN_ROOT/plan.json"
"$SELECT_BIN" resolve --catalog "$CATALOG" --manifest "$RUN_ROOT/manifest.json" \
  --requested "$REQUESTED" --plan "$RUN_ROOT/plan.json" --impact "$IMPACT" --out "$RUN_ROOT/gates.json"

python3 - "$RUN_ROOT/gates.json" <<'EOF'
import json, sys
gates = json.load(open(sys.argv[1]))
for cell in gates["unavailable"]:
    print(f'unavailable cell {cell["case_id"]} v{cell["case_version"]} {cell["cell_id"]}: {cell["reason"]}')
for profile in gates["unbound_profiles"]:
    print(f'unbound profile {profile["profile"]}: {profile["reason"]}')
EOF

# Run every bound gate to completion, recording pass/fail per gate id. Cargo
# gates serialize on the cooperative build slot; plain gates run directly.
: > "$RUN_ROOT/gate-results.tsv"
run_gate() {
  local kind="$1" id="$2" log="$3"
  shift 3
  echo "--- gate $kind/$id: $*"
  if [ "$1" = "cargo" ]; then
    if "$ROOT/bin/scopebase-build" --lock-root "$LOCK_ROOT" --resource build -- "$@" >"$log" 2>&1; then
      echo "gate $kind/$id: PASS"
      printf '%s\t%s\tpass\n' "$kind" "$id" >> "$RUN_ROOT/gate-results.tsv"
    else
      echo "gate $kind/$id: FAIL (see $log)"
      printf '%s\t%s\tfail\n' "$kind" "$id" >> "$RUN_ROOT/gate-results.tsv"
    fi
  else
    if "$@" >"$log" 2>&1; then
      echo "gate $kind/$id: PASS"
      printf '%s\t%s\tpass\n' "$kind" "$id" >> "$RUN_ROOT/gate-results.tsv"
    else
      echo "gate $kind/$id: FAIL (see $log)"
      printf '%s\t%s\tfail\n' "$kind" "$id" >> "$RUN_ROOT/gate-results.tsv"
    fi
  fi
}

# The gate loop runs in bash over argv rows emitted as TSV:
python3 -c '
import json, shlex, sys
gates = json.load(open(sys.argv[1]))
for kind, entries, key in (("fast", gates["fast_gates"], "gate_id"),
                           ("profile", gates["profile_gates"], "profile"),
                           ("cell", gates["runnable"], "cell_id")):
    for entry in entries:
        gid = entry.get("gate_id") or entry.get("id") or entry.get(key, "?")
        print(f"{kind}\t{gid}\t" + "\t".join(shlex.quote(a) for a in entry["argv"]))
' "$RUN_ROOT/gates.json" > "$RUN_ROOT/gate-argv.tsv"
gate_seq=0
while IFS=$'\t' read -r kind gid argv_rest; do
  [ -n "$kind" ] || continue
  # shellcheck disable=SC2086
  eval "set -- $argv_rest"
  # Sequence keeps logs distinct when several profiles share one gate id
  # (e.g. the same package suite backs multiple profiles).
  gate_seq=$((gate_seq + 1))
  safe="$(printf '%s-%s-%d' "$kind" "$gid" "$gate_seq" | tr -c 'A-Za-z0-9-_.' '_')"
  run_gate "$kind" "$gid" "$RUN_ROOT/logs/$safe.log" "$@"
done < "$RUN_ROOT/gate-argv.tsv"

FAST_TOTAL="$(grep -c '^fast' "$RUN_ROOT/gate-results.tsv" || true)"
FAST_PASSED="$(grep -c '^fast.*pass$' "$RUN_ROOT/gate-results.tsv" || true)"
echo "fast gates: ${FAST_PASSED:-0}/${FAST_TOTAL:-0} passed"
FAILED="$(grep -c 'fail$' "$RUN_ROOT/gate-results.tsv" || true)"

# Executed cells: runnable cells whose gate command passed. Inherited evidence
# is always empty in v1: no prior-receipt store is bound, so unchanged required
# cells are reported explicitly without inherited cover.
python3 - "$RUN_ROOT/gates.json" "$RUN_ROOT/gate-results.tsv" "$RUN_ROOT/executed.json" <<'EOF'
import json, sys
gates = json.load(open(sys.argv[1]))
passed = set()
for line in open(sys.argv[2]):
    parts = line.rstrip("\n").split("\t")
    if len(parts) == 3 and parts[2] == "pass":
        passed.add((parts[0], parts[1]))
executed = []
for entry in gates["runnable"]:
    gid = entry.get("gate_id", entry.get("cell_id", "?"))
    if ("cell", gid) in passed:
        executed.append({"case_id": entry["case_id"],
                         "case_version": entry["case_version"],
                         "cell_id": entry["cell_id"]})
json.dump({"executed": executed, "inherited": []}, open(sys.argv[3], "w"), indent=1)
print(f"executed cells: {len(executed)}")
EOF

"$SELECT_BIN" account --catalog "$CATALOG" --manifest "$RUN_ROOT/manifest.json" \
  --requested "$REQUESTED" --executed "$RUN_ROOT/executed.json" --out "$RUN_ROOT/accounting.json"

ACCOUNTING="$(python3 -c 'import json,sys; a=json.load(open(sys.argv[1])); print(a["status"], a["scope"], str(a["full_matrix_complete"]).lower(), len(a["missing_selected"]))' "$RUN_ROOT/accounting.json")"
echo "accounting summary: $ACCOUNTING"

# Retry-gate verdict over this run's own outcome: pass iff every executed gate
# passed. The detail always cites the accounting state so a resolved verdict
# can never be misread as qualification; unavailable required checks keep the
# final exit code at 3 (incomplete) even when every runnable gate passed.
if [ "${FAILED:-0}" -eq 0 ]; then
  OUTCOME="pass"
else
  OUTCOME="semantic_failure"
fi
python3 - "$OUTCOME" "$ACCOUNTING" "$RUN_ROOT/attempts.json" <<'EOF'
import json, sys
outcome, accounting, out = sys.argv[1], sys.argv[2], sys.argv[3]
detail = ("run outcome: all runnable gates passed" if outcome == "pass"
          else "run outcome: one or more gates failed")
json.dump({"attempts": [{"attempt": 1, "outcome": outcome,
                         "detail": f"{detail}; accounting {accounting} (see accounting.json)"}],
           "resolutions": []}, open(out, "w"), indent=1)
EOF
set +e
"$SELECT_BIN" gate --attempts "$RUN_ROOT/attempts.json" --out "$RUN_ROOT/verdict.json"
GATE_EXIT=$?
set -e

FULL="$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["full_matrix_complete"]).lower())' "$RUN_ROOT/accounting.json")"
if [ "${FAILED:-0}" -ne 0 ]; then
  echo "verdict=FAILED gate_exit=$GATE_EXIT ($FAILED gate failures)"
  exit 1
fi
if [ "$FULL" = "true" ] && [ "$GATE_EXIT" -eq 0 ]; then
  echo "verdict=COMPLETE"
  exit 0
fi
# Intended narrowed-complete signal, not an error: no gate failed, but the
# full matrix stays unattested (FULL=false). Callers must not report this as
# a pass; only exit 0 attests full_matrix_complete. Retrying the same
# selection cannot turn it green — the missing checks need executable
# bindings or a broader run (see docs/testing/ci.md).
echo "verdict=INCOMPLETE gate_exit=$GATE_EXIT (no gate failures; required checks unavailable or unexecuted)"
exit 3
