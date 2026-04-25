"""Loop 8 — Oracle self-calibration.

Records the direction of every oracle disagreement
(`interpreter_stricter` / `bpf_stricter`) into
<kb>/meta/oracle_calibration.jsonl. A periodic report flags
systematic bias when the same direction dominates above a threshold
over a rolling window.

Doesn't auto-fix anything — surfaces patterns a human reviewing
individual disagreements would miss. Per HONE_SELF_IMPROVEMENT.md
loop 8.
"""
from .engine import (
  CalibrationReport,
  Direction,
  build_report,
  record_disagreement,
)

__all__ = [
  "CalibrationReport",
  "Direction",
  "build_report",
  "record_disagreement",
]
