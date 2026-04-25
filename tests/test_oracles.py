"""Tests for the oracle wrappers — parsing, error paths."""
from __future__ import annotations
from pathlib import Path

import pytest

from harness.oracles import bpf_runner, fwl_subprocess, interpreter


_SAMPLE_FWL_TEST_OUTPUT = """\
PASS  always_allow.pkt  (always-allow program returns XDP_PASS)
      spec         pass
      interpreter  pass
      bpf          skip  [skip: BPF_PROG_RUN unavailable; clang ok]
PASS  drop_tcp.pkt  (drop tcp packet)
      spec         pass
      interpreter  pass
      bpf          pass
FAIL  bad_case.pkt  (bad expected.bpf_action)
      spec         pass
      interpreter  fail  -- expected XDP_DROP, got XDP_PASS
      bpf          skip  [skip: skipped because compile failed]

3/3 cases passed
"""


def test_run_corpus_parses_pass_skip_fail():
  inv = fwl_subprocess.FwlInvocation(
    argv=("fwl", "test", "x"),
    exit_code=0,
    stdout=_SAMPLE_FWL_TEST_OUTPUT,
    stderr="",
  )
  verdict = bpf_runner._parse_run_output(inv)
  assert verdict.total == 3
  assert verdict.passed == 3  # parser reads totals from final summary
  assert len(verdict.cases) == 3
  by_file = {c.pkt_file: c for c in verdict.cases}
  always = by_file["always_allow.pkt"]
  assert always.passed
  assert always.oracles == {
    "spec": "pass", "interpreter": "pass", "bpf": "skip",
  }
  assert "BPF_PROG_RUN unavailable" in always.details["bpf"]
  drop = by_file["drop_tcp.pkt"]
  assert drop.oracles["bpf"] == "pass"
  assert "bpf" not in drop.details
  bad = by_file["bad_case.pkt"]
  assert not bad.passed
  assert bad.oracles["interpreter"] == "fail"
  assert "expected XDP_DROP" in bad.details["interpreter"]


def test_run_corpus_handles_empty_output():
  inv = fwl_subprocess.FwlInvocation(
    argv=("fwl", "test", "x"), exit_code=2, stdout="", stderr="boom",
  )
  verdict = bpf_runner._parse_run_output(inv)
  assert verdict.cases == []
  assert verdict.total == 0
  assert not verdict.all_passed


_SAMPLE_INTERP_OUTPUT = "XDP_PASS (default: allow)\n"


def test_interpret_parses_action_and_label(monkeypatch):
  def fake_run_fwl(*args, **kwargs):
    return fwl_subprocess.FwlInvocation(
      argv=tuple(args), exit_code=0,
      stdout=_SAMPLE_INTERP_OUTPUT, stderr="",
    )
  monkeypatch.setattr(interpreter, "run_fwl", fake_run_fwl)
  res = interpreter.interpret(
    "fwl", Path("a.fw"), Path("a.pkt"),
  )
  assert res.action == "XDP_PASS"
  assert res.rule_label == "default: allow"


def test_interpret_returns_none_action_on_compile_failure(monkeypatch):
  def fake_run_fwl(*args, **kwargs):
    return fwl_subprocess.FwlInvocation(
      argv=tuple(args), exit_code=1,
      stdout="", stderr="error: pkt.dst_port requires guard",
    )
  monkeypatch.setattr(interpreter, "run_fwl", fake_run_fwl)
  res = interpreter.interpret(
    "fwl", Path("a.fw"), Path("a.pkt"),
  )
  assert res.action is None
  assert "guard" in res.invocation.stderr


def test_resolve_fwl_bin_explicit_arg(tmp_path):
  fake = tmp_path / "fwl"
  fake.write_text("#!/bin/sh\necho ok")
  fake.chmod(0o755)
  assert fwl_subprocess.resolve_fwl_bin(str(fake)) == str(fake)


def test_resolve_fwl_bin_missing_path(tmp_path):
  with pytest.raises(fwl_subprocess.FwlNotFound):
    fwl_subprocess.resolve_fwl_bin(str(tmp_path / "nope"))
