"""Shared types + helpers for discovery strategies.

Every strategy produces (program, packet, expected) triples. The
runner executes them through the oracles and classifies the outcome.
The strategy itself stays oblivious to the runner — it just yields
candidates.
"""
from __future__ import annotations
import enum
from dataclasses import dataclass, field


class Verdict(str, enum.Enum):
  """Classification of one (program, packet) probe."""
  AGREE = "agree"
  ORACLE_DIVERGENCE = "oracle_divergence"
  COMPILE_FAILED = "compile_failed"
  RUNNER_ERROR = "runner_error"


@dataclass
class Candidate:
  """One (program, packet, expected) triple a strategy proposes."""
  name: str                    # slug for filenames + finding ids
  fw_source: str               # full .fw program text
  pkt_yaml: str                # full .pkt YAML body
  expected_action: str | None  # "allow" | "drop" | None (compile-failure)
  rationale: str = ""          # one-line description of what this tests
  tags: list[str] = field(default_factory=list)


@dataclass
class Probe:
  """Result of running one Candidate through the oracles."""
  candidate: Candidate
  verdict: Verdict
  interpreter_action: str | None
  bpf_action: str | None
  detail: str = ""


def slug(text: str, limit: int = 80) -> str:
  """Filesystem-safe slug (lowercase, snake_case, length-capped)."""
  import re
  s = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
  return s[:limit]


# Stub for type hints — the actual Strategy protocol is just any
# callable that returns an Iterable[Candidate] given a target.
StrategyFn = "callable[[Path], Iterable[Candidate]]"
