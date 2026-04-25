"""Direction-aware oracle disagreement log + bias detector.

We map each disagreement to one of three labels:

  interpreter_stricter   interpreter said XDP_DROP, bpf said XDP_PASS
  bpf_stricter           bpf said XDP_DROP, interpreter said XDP_PASS
  unknown                one or both actions could not be parsed

When 80%+ of recent disagreements share a direction, the report
flags a systematic bias the operator should investigate (one oracle
may be drifting from spec for a particular construct).
"""
from __future__ import annotations
import enum
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


class Direction(str, enum.Enum):
  """Which oracle returned the stricter (drop) action."""
  INTERPRETER_STRICTER = "interpreter_stricter"
  BPF_STRICTER = "bpf_stricter"
  UNKNOWN = "unknown"


@dataclass
class CalibrationReport:
  """Aggregate over the recent disagreement log."""
  total: int = 0
  by_direction: dict[str, int] = field(default_factory=dict)
  flagged_bias: str | None = None
  ratio: float = 0.0
  recent_examples: list[dict] = field(default_factory=list)


def _calibration_path(kb_root: Path) -> Path:
  d = kb_root / "meta"
  d.mkdir(parents=True, exist_ok=True)
  return d / "oracle_calibration.jsonl"


def _classify_direction(
  interpreter_action: str | None, bpf_action: str | None,
) -> Direction:
  """Map two oracle actions to a Direction enum."""
  if not interpreter_action or not bpf_action:
    return Direction.UNKNOWN
  if interpreter_action == bpf_action:
    return Direction.UNKNOWN  # Caller shouldn't have logged this case.
  if interpreter_action == "XDP_DROP" and bpf_action == "XDP_PASS":
    return Direction.INTERPRETER_STRICTER
  if bpf_action == "XDP_DROP" and interpreter_action == "XDP_PASS":
    return Direction.BPF_STRICTER
  return Direction.UNKNOWN


def record_disagreement(
  kb_root: Path,
  test_id: str,
  interpreter_action: str | None,
  bpf_action: str | None,
  context: dict | None = None,
) -> Direction:
  """Append one disagreement event; return the inferred direction."""
  direction = _classify_direction(interpreter_action, bpf_action)
  event = {
    "ts": datetime.now(timezone.utc).isoformat(),
    "test_id": test_id,
    "interpreter": interpreter_action,
    "bpf": bpf_action,
    "direction": direction.value,
  }
  if context:
    event["context"] = context
  with _calibration_path(kb_root).open("a", encoding="utf-8") as f:
    f.write(json.dumps(event) + "\n")
  return direction


def build_report(
  kb_root: Path,
  window: int = 100,
  bias_threshold: float = 0.8,
) -> CalibrationReport:
  """Read the most recent `window` events, count by direction, flag
  bias when one direction's share is >= bias_threshold."""
  path = _calibration_path(kb_root)
  if not path.exists():
    return CalibrationReport()
  lines = path.read_text(encoding="utf-8").splitlines()[-window:]
  by_direction: dict[str, int] = {}
  examples: list[dict] = []
  for line in lines:
    if not line.strip():
      continue
    try:
      event = json.loads(line)
    except json.JSONDecodeError:
      continue
    d = event.get("direction", Direction.UNKNOWN.value)
    by_direction[d] = by_direction.get(d, 0) + 1
    if len(examples) < 5:
      examples.append({
        "ts": event.get("ts"),
        "test_id": event.get("test_id"),
        "interpreter": event.get("interpreter"),
        "bpf": event.get("bpf"),
        "direction": d,
      })
  total = sum(by_direction.values())
  report = CalibrationReport(
    total=total,
    by_direction=by_direction,
    recent_examples=examples,
  )
  if total >= 5:
    # Drop UNKNOWN from the bias check — only directional events count.
    directional = {
      k: v for k, v in by_direction.items()
      if k != Direction.UNKNOWN.value
    }
    if directional:
      top = max(directional, key=directional.get)
      ratio = directional[top] / sum(directional.values())
      report.ratio = ratio
      if ratio >= bias_threshold:
        report.flagged_bias = top
  return report
