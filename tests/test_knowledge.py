"""Round-trip tests for the knowledge-base markdown writer/reader."""
from __future__ import annotations
from datetime import date
from pathlib import Path

import pytest

from harness.knowledge import (
  Finding, Layer, Miss, Pattern, Severity,
  read_finding, read_miss, read_pattern,
  scan_knowledge_base,
  write_finding, write_miss, write_pattern,
)


def test_finding_roundtrip(tmp_path: Path) -> None:
  finding = Finding(
    id="2026-04-25-cidr-prefix-overflow",
    summary="CIDR prefix > 32 crashed parser",
    body="## Root Cause\nValueError leaked.\n\n## Fix\nCommit abc123.",
    protocols=["ipv4"],
    builtins=[],
    severity=Severity.MEDIUM,
    layer=Layer.COMPILER,
    pattern_tags=["range-validation"],
    status="fixed",
    source_file="examples/internal_network.fw",
    created=date(2026, 4, 25),
    pkt_path="corpus/cidr_prefix_overflow.pkt",
  )
  out = write_finding(finding, tmp_path)
  loaded = read_finding(out)
  assert loaded.id == finding.id
  assert loaded.severity == Severity.MEDIUM
  assert loaded.layer == Layer.COMPILER
  assert loaded.protocols == ["ipv4"]
  assert loaded.pattern_tags == ["range-validation"]
  assert loaded.status == "fixed"
  assert loaded.created == date(2026, 4, 25)
  assert loaded.pkt_path == "corpus/cidr_prefix_overflow.pkt"
  assert "CIDR prefix > 32" in loaded.summary


def test_miss_roundtrip(tmp_path: Path) -> None:
  miss = Miss(
    id="2026-04-25-frag-dos",
    hypothesis="IP frag offset could read past buffer",
    body="## Result\nCorrectly handled by the existing check.",
    protocols=["ipv4"],
    pattern_tags=["bounds-check"],
  )
  out = write_miss(miss, tmp_path)
  loaded = read_miss(out)
  assert loaded.id == miss.id
  assert "IP frag" in loaded.hypothesis
  assert loaded.pattern_tags == ["bounds-check"]


def test_pattern_roundtrip(tmp_path: Path) -> None:
  pattern = Pattern(
    id="claimed-vs-actual-length",
    description="Parsers that trust claimed length read past buffers.",
    body="## Check Strategy\n1. Compare claimed vs actual lengths.",
    known_instances=["finding/2026-04-25-wg-truncate"],
    protocols=["wg", "tcp", "ipv4"],
  )
  out = write_pattern(pattern, tmp_path)
  loaded = read_pattern(out)
  assert loaded.id == pattern.id
  assert loaded.protocols == ["wg", "tcp", "ipv4"]
  assert "claimed length" in loaded.description.lower()


def test_scan_knowledge_base(tmp_path: Path) -> None:
  write_finding(
    Finding(id="f1", summary="s", body="## Summary\ns"), tmp_path,
  )
  write_finding(
    Finding(id="f2", summary="s", body="## Summary\ns"), tmp_path,
  )
  write_miss(
    Miss(id="m1", hypothesis="h", body="## Hypothesis\nh"), tmp_path,
  )
  write_pattern(
    Pattern(id="p1", description="d", body="## Description\nd"), tmp_path,
  )
  findings, misses, patterns = scan_knowledge_base(tmp_path)
  assert len(findings) == 2
  assert {f.id for f in findings} == {"f1", "f2"}
  assert len(misses) == 1
  assert len(patterns) == 1


def test_reader_rejects_missing_frontmatter(tmp_path: Path) -> None:
  bad = tmp_path / "findings" / "broken.md"
  bad.parent.mkdir(parents=True)
  bad.write_text("# No frontmatter\n\nbody only", encoding="utf-8")
  with pytest.raises(ValueError, match="frontmatter"):
    read_finding(bad)
