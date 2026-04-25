"""Dataclasses for the mutation pipeline."""
from __future__ import annotations
import enum
from dataclasses import dataclass, field
from pathlib import Path


class MutationOutcome(str, enum.Enum):
  """Outcome of running one mutant through both oracles."""
  AGREE = "agree"
  DIVERGENT = "divergent"
  COMPILE_FAILED = "compile_failed"
  RUNNER_ERROR = "runner_error"


@dataclass
class Mutant:
  """One mutated (program, packet) candidate.

  `parent_finding_id` lets the kb cross-link a mutant-derived finding
  back to its origin; "related" propagates downstream.
  """
  name: str
  fw_source: str
  pkt_yaml: str
  rationale: str
  mutation: str
  parent_finding_id: str | None = None
  tags: list[str] = field(default_factory=list)


@dataclass
class MutationResult:
  """Aggregate outcome of one `hone mutate` invocation."""
  total: int = 0
  agree: int = 0
  divergent: int = 0
  compile_failed: int = 0
  runner_error: int = 0
  findings_written: list[Path] = field(default_factory=list)
  mutants_written: list[Path] = field(default_factory=list)
