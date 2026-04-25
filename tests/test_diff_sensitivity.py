"""Unit tests for the compiler-diff → constructs mapper."""
from __future__ import annotations
from pathlib import Path

import pytest

from harness.diff_sensitivity import diff_impact, load_construct_map
from harness.diff_sensitivity.engine import WILDCARD


_MAP = """
fwl/fwl/grammar.lark: [all]
fwl/fwl/interpreter.py: [interpreter, rate_limit]
fwl/fwl/emitter.py: [emitter, rate_limit]
"""


def _write_map(tmp: Path) -> Path:
  p = tmp / "construct_map.yaml"
  p.write_text(_MAP, encoding="utf-8")
  return p


def test_load_construct_map(tmp_path: Path) -> None:
  p = _write_map(tmp_path)
  m = load_construct_map(p)
  assert m["fwl/fwl/grammar.lark"] == ["all"]
  assert "rate_limit" in m["fwl/fwl/interpreter.py"]


def test_load_construct_map_missing_returns_empty(tmp_path: Path) -> None:
  assert load_construct_map(tmp_path / "nope.yaml") == {}


def test_diff_impact_maps_known_files(tmp_path: Path) -> None:
  cmap = _write_map(tmp_path)
  imp = diff_impact(
    repo=tmp_path,
    base="HEAD~1",
    construct_map_path=cmap,
    changed_files=[
      "fwl/fwl/interpreter.py",
      "fwl/fwl/emitter.py",
    ],
  )
  assert "rate_limit" in imp.impacted_constructs
  assert "interpreter" in imp.impacted_constructs
  assert "emitter" in imp.impacted_constructs
  assert imp.unmapped_files == []


def test_diff_impact_marks_wildcard(tmp_path: Path) -> None:
  cmap = _write_map(tmp_path)
  imp = diff_impact(
    repo=tmp_path,
    base="HEAD~1",
    construct_map_path=cmap,
    changed_files=["fwl/fwl/grammar.lark"],
  )
  assert WILDCARD in imp.impacted_constructs


def test_diff_impact_collects_unmapped(tmp_path: Path) -> None:
  cmap = _write_map(tmp_path)
  imp = diff_impact(
    repo=tmp_path,
    base="HEAD~1",
    construct_map_path=cmap,
    changed_files=["unrelated/file.cc", "fwl/fwl/interpreter.py"],
  )
  assert imp.unmapped_files == ["unrelated/file.cc"]
  assert "rate_limit" in imp.impacted_constructs


def test_load_construct_map_rejects_non_mapping(tmp_path: Path) -> None:
  p = tmp_path / "bad.yaml"
  p.write_text("- a\n- b\n", encoding="utf-8")
  with pytest.raises(ValueError, match="mapping"):
    load_construct_map(p)
