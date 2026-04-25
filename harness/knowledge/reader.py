"""Parse markdown + YAML-frontmatter back into knowledge dataclasses.

Tolerates trailing whitespace and missing optional fields. Strict on
the structural invariant (must start with `---\\nyaml\\n---\\n`); a file
that doesn't match is skipped with a clear message.
"""
from __future__ import annotations
import re
from datetime import date
from pathlib import Path
from typing import Iterable

import yaml

from .types import Finding, Layer, Miss, Pattern, Severity


_FRONTMATTER_RE = re.compile(
  r"\A---\s*\n(?P<yaml>.*?)\n---\s*\n(?P<body>.*)\Z",
  re.DOTALL,
)


def _split(text: str) -> tuple[dict, str]:
  """Return (frontmatter dict, body text). Raises ValueError on bad shape."""
  match = _FRONTMATTER_RE.match(text)
  if not match:
    raise ValueError(
      "expected YAML frontmatter delimited by '---' at top of file"
    )
  fm = yaml.safe_load(match.group("yaml")) or {}
  if not isinstance(fm, dict):
    raise ValueError("frontmatter must be a YAML mapping")
  return fm, match.group("body")


def _coerce_date(value) -> date:
  """Frontmatter dates can be `date` (PyYAML's default) or ISO strings."""
  if isinstance(value, date):
    return value
  if isinstance(value, str):
    return date.fromisoformat(value)
  raise ValueError(f"unrecognized date value: {value!r}")


def _strip_id_prefix(raw_id: str) -> str:
  """`finding/2026-04-25-X` -> `2026-04-25-X`."""
  return raw_id.split("/", 1)[1] if "/" in raw_id else raw_id


def read_finding(path: Path) -> Finding:
  """Load one finding markdown file."""
  fm, body = _split(path.read_text(encoding="utf-8"))
  return Finding(
    id=_strip_id_prefix(fm.get("id", path.stem)),
    summary=_extract_section(body, "Summary") or "",
    body=body,
    protocols=fm.get("protocol", []) or [],
    builtins=fm.get("builtins", []) or [],
    severity=Severity(fm.get("severity", "medium")),
    layer=Layer(fm.get("layer", "compiler")),
    pattern_tags=fm.get("pattern_tags", []) or [],
    status=fm.get("status", "open"),
    source_file=fm.get("source_file"),
    created=_coerce_date(fm.get("created", date.today())),
    pkt_path=fm.get("pkt_path"),
  )


def read_miss(path: Path) -> Miss:
  """Load one miss markdown file."""
  fm, body = _split(path.read_text(encoding="utf-8"))
  return Miss(
    id=_strip_id_prefix(fm.get("id", path.stem)),
    hypothesis=_extract_section(body, "Hypothesis") or "",
    body=body,
    protocols=fm.get("protocol", []) or [],
    builtins=fm.get("builtins", []) or [],
    pattern_tags=fm.get("pattern_tags", []) or [],
    source_file=fm.get("source_file"),
    created=_coerce_date(fm.get("created", date.today())),
  )


def read_pattern(path: Path) -> Pattern:
  """Load one pattern markdown file."""
  fm, body = _split(path.read_text(encoding="utf-8"))
  return Pattern(
    id=_strip_id_prefix(fm.get("id", path.stem)),
    description=_extract_section(body, "Description") or "",
    body=body,
    known_instances=fm.get("known_instances", []) or [],
    protocols=fm.get("protocol", []) or [],
    created=_coerce_date(fm.get("created", date.today())),
  )


def scan_knowledge_base(kb_root: Path) -> tuple[
  list[Finding], list[Miss], list[Pattern]
]:
  """Walk a knowledge base directory and parse every entity."""
  findings: list[Finding] = []
  misses: list[Miss] = []
  patterns: list[Pattern] = []
  for f in _walk(kb_root / "findings"):
    findings.append(read_finding(f))
  for f in _walk(kb_root / "misses"):
    misses.append(read_miss(f))
  for f in _walk(kb_root / "patterns"):
    patterns.append(read_pattern(f))
  return findings, misses, patterns


def _walk(d: Path) -> Iterable[Path]:
  """Yield every .md file under `d` (sorted), or nothing if `d` missing."""
  if not d.exists():
    return ()
  return sorted(d.glob("*.md"))


def _extract_section(body: str, header: str) -> str | None:
  """Grab text under a `## <header>` markdown section.

  Returns the text up to the next header at the same level (or end of
  document). Used to recover Summary/Hypothesis/Description back out
  of the body when populating dataclass fields.
  """
  pattern = re.compile(
    rf"^##\s+{re.escape(header)}\s*\n(.*?)(?=^##\s+|\Z)",
    re.MULTILINE | re.DOTALL,
  )
  m = pattern.search(body)
  return m.group(1).strip() if m else None
