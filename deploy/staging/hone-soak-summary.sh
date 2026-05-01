#!/usr/bin/env bash
# hone-soak-summary.sh — daily soak digest mailer (optional).
#
# Tails the day's per-tick logs, the spend total, and the diff
# against the previous day's findings count, and emails the result
# to OPERATOR_EMAIL. Skipped silently when OPERATOR_EMAIL is unset.
#
# Cron / systemd-timer this at 00:05 UTC. Won't run more than once
# a day per host.
#
# Environment:
#   STATE_DIR        — soak state root (default: $PWD/.state/soak)
#   HONE_KB          — knowledge base for findings count
#   OPERATOR_EMAIL   — recipient (mailer is a no-op when unset)
#   MAIL_CMD         — sendmail-compatible binary (default: mail)

set -uo pipefail

if [ -z "${OPERATOR_EMAIL:-}" ]; then
  exit 0
fi

STATE_DIR="${STATE_DIR:-${PWD}/.state/soak}"
HONE_KB="${HONE_KB:-../f-knowlege-base}"
MAIL_CMD="${MAIL_CMD:-mail}"

yesterday="$(date -u -d 'yesterday' +%Y-%m-%d)"
day_dir="${STATE_DIR}/${yesterday}"

if [ ! -d "${day_dir}" ]; then
  echo "no soak data for ${yesterday}; skipping summary"
  exit 0
fi

ticks="$(find "${day_dir}" -maxdepth 1 -name '*.log' | wc -l)"
spent="$(cat "${day_dir}/spend.txt" 2>/dev/null || echo 0)"
findings_today="$(find "${HONE_KB}/findings" -name "${yesterday}-*.md" \
    2>/dev/null | wc -l)"
fails="$(grep -h "FAIL" "${day_dir}"/*.log 2>/dev/null | wc -l)"

subject="hone-soak ${yesterday}: ${ticks} ticks, ${findings_today} new findings, \$${spent} spent"
body="$(cat <<EOF
hone-soak summary for ${yesterday} (UTC).

Ticks: ${ticks}
Spend: \$${spent} (cap: \${HONE_DAILY_BUDGET_USD:-10})
New findings: ${findings_today}
Test failures across all ticks: ${fails}

Per-tick logs: ${day_dir}/

Last tick tail:
$(tail -20 "$(ls -t "${day_dir}"/*.log | head -1)" 2>/dev/null || echo '(none)')
EOF
)"

if ! command -v "${MAIL_CMD}" >/dev/null; then
  echo "${MAIL_CMD} not on PATH; skipping mail (subject: ${subject})"
  exit 0
fi

printf '%s\n' "${body}" | "${MAIL_CMD}" -s "${subject}" "${OPERATOR_EMAIL}"
