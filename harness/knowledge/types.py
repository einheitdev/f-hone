"""Dataclasses for the three knowledge-base entity kinds.

Findings, misses, and patterns all share a markdown + YAML-frontmatter
on-disk shape. The dataclasses here are the in-memory representation;
writer.py and reader.py do the round-trip.
"""
from __future__ import annotations
import enum
from dataclasses import dataclass, field
from datetime import date


class Severity(str, enum.Enum):
  """Finding severity. String values match the spec's frontmatter tags."""
  LOW = "low"
  MEDIUM = "medium"
  HIGH = "high"
  CRITICAL = "critical"


class Layer(str, enum.Enum):
  """Which layer the bug lives in (per F_SECURITY_HARNESS.md)."""
  USER_RULE = "user_rule"
  COMPILER = "compiler"
  BUILTIN = "builtin"


@dataclass
class Finding:
  """A confirmed bug.

  Stored at <kb>/findings/<id>.md. The id is also the filename without
  the .md suffix, e.g. `2026-04-25-cidr-prefix-overflow`.

  `body` is the full markdown body (everything after the YAML
  frontmatter). It typically contains Summary / Root Cause /
  Classification / PoC / Fix / Related sections.
  """
  id: str
  summary: str
  body: str
  protocols: list[str] = field(default_factory=list)
  builtins: list[str] = field(default_factory=list)
  severity: Severity = Severity.MEDIUM
  layer: Layer = Layer.COMPILER
  pattern_tags: list[str] = field(default_factory=list)
  status: str = "open"
  source_file: str | None = None
  created: date = field(default_factory=date.today)
  pkt_path: str | None = None


@dataclass
class Miss:
  """A hypothesis that was tested and falsified.

  Stored at <kb>/misses/<id>.md. Misses are as valuable as findings for
  retrieval — they tell future agents "we already tried this, don't
  burn API budget reproposing it."
  """
  id: str
  hypothesis: str
  body: str
  protocols: list[str] = field(default_factory=list)
  builtins: list[str] = field(default_factory=list)
  pattern_tags: list[str] = field(default_factory=list)
  source_file: str | None = None
  created: date = field(default_factory=date.today)


@dataclass
class Pattern:
  """An abstracted bug class.

  Stored at <kb>/patterns/<id>.md. Patterns emerge from clustering N+
  related findings — they describe the *shape* of the bug class and
  point at where to check next, not just what was found.
  """
  id: str
  description: str
  body: str
  check_strategy: str = ""
  known_instances: list[str] = field(default_factory=list)
  protocols: list[str] = field(default_factory=list)
  created: date = field(default_factory=date.today)
