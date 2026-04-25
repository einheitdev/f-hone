"""Unit tests for the oracle direction logger + bias detector."""
from __future__ import annotations
from pathlib import Path

from harness.calibration import (
  Direction,
  build_report,
  record_disagreement,
)


def test_direction_classification_interp_strict(tmp_path: Path) -> None:
  d = record_disagreement(tmp_path, "case1", "XDP_DROP", "XDP_PASS")
  assert d == Direction.INTERPRETER_STRICTER


def test_direction_classification_bpf_strict(tmp_path: Path) -> None:
  d = record_disagreement(tmp_path, "case1", "XDP_PASS", "XDP_DROP")
  assert d == Direction.BPF_STRICTER


def test_direction_classification_unknown_when_missing(tmp_path: Path) -> None:
  d = record_disagreement(tmp_path, "case1", None, "XDP_DROP")
  assert d == Direction.UNKNOWN


def test_build_report_empty(tmp_path: Path) -> None:
  r = build_report(tmp_path)
  assert r.total == 0
  assert r.flagged_bias is None


def test_build_report_flags_bias(tmp_path: Path) -> None:
  for i in range(8):
    record_disagreement(
      tmp_path, f"case{i}", "XDP_DROP", "XDP_PASS",
    )
  for i in range(2):
    record_disagreement(
      tmp_path, f"case_other{i}", "XDP_PASS", "XDP_DROP",
    )
  r = build_report(tmp_path, window=20, bias_threshold=0.7)
  assert r.flagged_bias == Direction.INTERPRETER_STRICTER.value
  assert r.ratio >= 0.7


def test_build_report_no_bias_below_threshold(tmp_path: Path) -> None:
  for i in range(5):
    record_disagreement(tmp_path, f"a{i}", "XDP_DROP", "XDP_PASS")
  for i in range(5):
    record_disagreement(tmp_path, f"b{i}", "XDP_PASS", "XDP_DROP")
  r = build_report(tmp_path, window=20, bias_threshold=0.8)
  assert r.flagged_bias is None


def test_build_report_window_limits(tmp_path: Path) -> None:
  for i in range(50):
    record_disagreement(tmp_path, f"old{i}", "XDP_DROP", "XDP_PASS")
  for i in range(10):
    record_disagreement(tmp_path, f"new{i}", "XDP_PASS", "XDP_DROP")
  r = build_report(tmp_path, window=10, bias_threshold=0.8)
  assert r.total == 10
  assert r.flagged_bias == Direction.BPF_STRICTER.value
