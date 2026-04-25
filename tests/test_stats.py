"""Unit tests for the report aggregator."""
from __future__ import annotations
import json
from datetime import date
from pathlib import Path

from harness.knowledge import (
  Finding, Layer, Miss, Pattern, Severity,
  write_finding, write_miss, write_pattern,
)
from harness.reporting.stats import (
  build_report, render_json,
)


def _seed(tmp: Path) -> None:
  """Populate a small kb with a mix of findings/misses/patterns."""
  write_finding(Finding(
    id="2026-04-01-a",
    summary="A1",
    body="## Summary\nA1",
    protocols=["tcp"],
    severity=Severity.HIGH,
    layer=Layer.COMPILER,
    pattern_tags=["bounds-check"],
    status="open",
    created=date(2026, 4, 1),
  ), tmp)
  write_finding(Finding(
    id="2026-04-10-b",
    summary="B1",
    body="## Summary\nB1",
    protocols=["udp"],
    severity=Severity.MEDIUM,
    layer=Layer.BUILTIN,
    pattern_tags=[],
    status="fixed",
    created=date(2026, 4, 10),
  ), tmp)
  write_finding(Finding(
    id="2026-04-20-c",
    summary="C1",
    body="## Summary\nC1",
    protocols=["tcp", "ipv4"],
    severity=Severity.LOW,
    layer=Layer.COMPILER,
    pattern_tags=["bounds-check"],
    status="open",
    created=date(2026, 4, 20),
  ), tmp)
  write_miss(Miss(
    id="2026-04-05-m",
    hypothesis="frag offset OOB",
    body="## Hypothesis\nfrag offset OOB",
    protocols=["ipv4"],
    pattern_tags=["bounds-check"],
    created=date(2026, 4, 5),
  ), tmp)
  write_pattern(Pattern(
    id="bounds-check",
    description="bounds-check pattern",
    body="## Description\nbounds",
    known_instances=[
      "finding/2026-04-01-a", "finding/2026-04-20-c",
    ],
    created=date(2026, 4, 12),
  ), tmp)


def test_build_report_counts(tmp_path: Path) -> None:
  _seed(tmp_path)
  stats = build_report(tmp_path)
  assert stats.total_findings == 3
  assert stats.total_misses == 1
  assert stats.total_patterns == 1
  assert stats.findings_by_status["open"] == 2
  assert stats.findings_by_status["fixed"] == 1
  assert stats.findings_by_severity["high"] == 1
  assert stats.findings_by_severity["medium"] == 1
  assert stats.findings_by_severity["low"] == 1
  assert stats.findings_by_protocol["tcp"] == 2
  assert stats.findings_by_protocol["udp"] == 1
  assert stats.findings_by_protocol["ipv4"] == 1
  assert stats.findings_by_pattern["bounds-check"] == 2
  # b has no pattern tag and no pattern reference -> uncovered
  assert "2026-04-10-b" in stats.uncovered_findings
  assert "2026-04-01-a" not in stats.uncovered_findings


def test_build_report_cutoff(tmp_path: Path) -> None:
  _seed(tmp_path)
  stats = build_report(tmp_path, cutoff=date(2026, 4, 15))
  assert stats.total_findings == 1
  assert stats.findings_by_day == {"2026-04-20": 1}
  assert stats.cutoff == "2026-04-15"


def test_render_json_round_trips(tmp_path: Path) -> None:
  _seed(tmp_path)
  stats = build_report(tmp_path)
  payload = json.loads(render_json(stats))
  assert payload["total_findings"] == 3
  assert payload["findings_by_protocol"]["tcp"] == 2


def test_empty_kb(tmp_path: Path) -> None:
  stats = build_report(tmp_path)
  assert stats.total_findings == 0
  assert stats.total_misses == 0
  assert stats.uncovered_findings == []
