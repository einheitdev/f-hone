"""Serialize Finding/Miss/Pattern dataclasses to markdown on disk.

Frontmatter is YAML between `---` markers (Jekyll/Hugo convention,
matches the spec at HONE_REPO_DESIGN.md "Front-matter format").
The body is appended verbatim after the closing `---`.
"""
from __future__ import annotations
from datetime import date
from pathlib import Path

import yaml

from .types import Finding, Miss, Pattern


def _emit(frontmatter: dict, body: str) -> str:
  """Stitch a YAML frontmatter block + markdown body into one document."""
  yml = yaml.safe_dump(
    frontmatter, sort_keys=False, default_flow_style=None
  ).rstrip()
  body = body.strip()
  return f"---\n{yml}\n---\n\n{body}\n"


def _date_to_str(d: date) -> str:
  """Frontmatter dates render as ISO yyyy-mm-dd strings."""
  return d.isoformat()


def write_finding(finding: Finding, kb_root: Path) -> Path:
  """Write a Finding to <kb_root>/findings/<id>.md and return the path."""
  fm = {
    "id": f"finding/{finding.id}",
    "type": "finding",
    "protocol": finding.protocols,
    "builtins": finding.builtins,
    "severity": finding.severity.value,
    "layer": finding.layer.value,
    "pattern_tags": finding.pattern_tags,
    "status": finding.status,
    "source_file": finding.source_file,
    "created": _date_to_str(finding.created),
    "pkt_path": finding.pkt_path,
  }
  out = kb_root / "findings" / f"{finding.id}.md"
  out.parent.mkdir(parents=True, exist_ok=True)
  body = f"# {finding.id}\n\n## Summary\n{finding.summary}\n\n{finding.body}"
  out.write_text(_emit(fm, body), encoding="utf-8")
  return out


def write_miss(miss: Miss, kb_root: Path) -> Path:
  """Write a Miss to <kb_root>/misses/<id>.md and return the path."""
  fm = {
    "id": f"miss/{miss.id}",
    "type": "miss",
    "protocol": miss.protocols,
    "builtins": miss.builtins,
    "pattern_tags": miss.pattern_tags,
    "source_file": miss.source_file,
    "created": _date_to_str(miss.created),
  }
  out = kb_root / "misses" / f"{miss.id}.md"
  out.parent.mkdir(parents=True, exist_ok=True)
  body = (
    f"# {miss.id}\n\n## Hypothesis\n{miss.hypothesis}\n\n{miss.body}"
  )
  out.write_text(_emit(fm, body), encoding="utf-8")
  return out


def write_pattern(pattern: Pattern, kb_root: Path) -> Path:
  """Write a Pattern to <kb_root>/patterns/<id>.md and return the path."""
  fm = {
    "id": f"pattern/{pattern.id}",
    "type": "pattern",
    "protocol": pattern.protocols,
    "known_instances": pattern.known_instances,
    "created": _date_to_str(pattern.created),
  }
  out = kb_root / "patterns" / f"{pattern.id}.md"
  out.parent.mkdir(parents=True, exist_ok=True)
  body = (
    f"# {pattern.id}\n\n## Description\n{pattern.description}\n\n"
    f"{pattern.body}"
  )
  out.write_text(_emit(fm, body), encoding="utf-8")
  return out
