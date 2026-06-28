#!/usr/bin/env bash
# hone-soak.sh — periodic verification while a dogfood bundle soaks.
#
# Runs once per invocation (the systemd timer drives the cadence):
#   1. hone regress on the kb corpus (interpreter + BPF when root).
#   2. hone fuzz boundary_probing.
#   3. hone fuzz oracle_divergence (one seed per cycle, rotating).
#   4. hone hunt against the live dogfood program — gated on the
#      day's spend tally vs. HONE_DAILY_BUDGET_USD (default $10).
#   5. hone tune.
#
# Per-run output goes to <STATE_DIR>/<UTC-date>/<HHMMSS>.log; the
# day's running spend lives in <STATE_DIR>/<UTC-date>/spend.txt.
#
# Environment:
#   HONE_KB             — knowledge-base root (default: ../f-knowlege-base)
#   HONE_FWL_REPO       — FWL repo root (default: ../f)
#   HONE_TARGET         — .fw to hunt against (default: ../f/fwl/examples/dogfood_v02.fw)
#   HONE_MODEL          — model passed to hone hunt (default: claude-opus-4-7)
#   HONE_DAILY_BUDGET_USD — soft cap on hone hunt spend per UTC day (default: 10)
#   STATE_DIR           — log + spend tracking root (default: $PWD/.state/soak)

set -uo pipefail

HONE_KB="${HONE_KB:-../f-knowlege-base}"
HONE_FWL_REPO="${HONE_FWL_REPO:-../f}"
HONE_TARGET="${HONE_TARGET:-${HONE_FWL_REPO}/fwl/examples/dogfood_v02.fw}"
HONE_MODEL="${HONE_MODEL:-claude-opus-4-7}"
HONE_DAILY_BUDGET_USD="${HONE_DAILY_BUDGET_USD:-10}"
STATE_DIR="${STATE_DIR:-${PWD}/.state/soak}"

today="$(date -u +%Y-%m-%d)"
now="$(date -u +%H%M%S)"
day_dir="${STATE_DIR}/${today}"
log_file="${day_dir}/${now}.log"
spend_file="${day_dir}/spend.txt"

mkdir -p "${day_dir}"
exec > >(tee -a "${log_file}") 2>&1

echo "=== hone-soak ${today}T${now}Z ==="
echo "kb=${HONE_KB}  target=${HONE_TARGET}  budget_usd=${HONE_DAILY_BUDGET_USD}"

# 1. regress
echo "--- regress ---"
if hone regress --corpus "${HONE_KB}/corpus/" 2>&1 | tail -3; then :; fi

# 2. boundary_probing fuzz
echo "--- fuzz: boundary_probing ---"
hone fuzz --strategy boundary_probing --kb "${HONE_KB}" \
    --fwl-bin "$(command -v fwl)" 2>&1 | tail -8

# 3. oracle_divergence — rotate seed by hour-of-day for variety
seed=$(( $(date -u +%H) % 4 ))
echo "--- fuzz: oracle_divergence seed=${seed} ---"
hone fuzz --strategy oracle_divergence --kb "${HONE_KB}" \
    --fwl-bin "$(command -v fwl)" --count 1000 --seed "${seed}" 2>&1 \
    | tail -8

# 4. hunt — only when the day's tally is below budget. The hone hunt
#    output reports `cost=$X.YY` on its summary line; we accumulate
#    those into spend.txt and skip the hunt once the day's sum hits
#    the cap.
spent="$(cat "${spend_file}" 2>/dev/null || echo 0)"
spent="${spent:-0}"
under_budget="$(awk -v s="${spent}" -v b="${HONE_DAILY_BUDGET_USD}" \
    'BEGIN { print (s+0 < b+0) ? 1 : 0 }')"
if [ "${under_budget}" = "1" ]; then
  echo "--- hunt: target=${HONE_TARGET} (spent=${spent}/${HONE_DAILY_BUDGET_USD}) ---"
  hunt_log="${day_dir}/${now}-hunt.log"
  hone hunt --kb "${HONE_KB}" --target "${HONE_TARGET}" \
      --max-turns 80 --model "${HONE_MODEL}" 2>&1 | tee "${hunt_log}"
  # Extract "cost=$N.NN" from the hunt summary and accumulate.
  cost="$(grep -oE 'cost=\$[0-9]+\.[0-9]+' "${hunt_log}" \
      | tail -1 | sed 's/cost=\$//')"
  cost="${cost:-0}"
  awk -v s="${spent}" -v c="${cost}" 'BEGIN { printf "%.2f\n", s+c }' \
      > "${spend_file}"
  echo "spend updated: $(cat "${spend_file}") / ${HONE_DAILY_BUDGET_USD}"
else
  echo "--- hunt SKIPPED: daily budget reached (${spent}/${HONE_DAILY_BUDGET_USD}) ---"
fi

# 5. tune
echo "--- tune ---"
hone tune --kb "${HONE_KB}" 2>&1 | tail -10

echo "=== hone-soak done ==="
