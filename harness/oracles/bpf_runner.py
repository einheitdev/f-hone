"""BPF runtime oracle.

Calls `fwl test <pkt_or_dir>` and parses the per-case verdict. The
runner already wraps clang + BPF_PROG_TEST_RUN, so we just need to
read its output.

The output format from fwl/runner.format_results() is:

  PASS <name>.pkt  (<friendly>)
        spec         pass
        interpreter  pass
        bpf          pass | skip [...] | fail -- <detail>
  ...
  N/M cases passed
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path

from .fwl_subprocess import FwlInvocation, run_fwl


@dataclass(frozen=True)
class CaseVerdict:
  """One .pkt case's three-oracle outcome from `fwl test`."""
  pkt_file: str
  friendly_name: str
  passed: bool
  # oracle name -> status ("pass" | "fail" | "skip" | "error").
  oracles: dict[str, str]
  # oracle name -> diagnostic text (skip reason or fail message).
  details: dict[str, str]


@dataclass(frozen=True)
class CorpusVerdict:
  """Result of running an entire directory through `fwl test`."""
  cases: list[CaseVerdict]
  total: int
  passed: int
  invocation: FwlInvocation

  @property
  def all_passed(self) -> bool:
    """True iff at least one case ran and every case passed.

    Returns False on an empty corpus or when the underlying `fwl test`
    invocation crashed before producing case output — empty success
    is almost always a regression-runner setup bug, not a clean pass.
    """
    return self.total > 0 and self.passed == self.total


_HEADER_RE = re.compile(
  r"^(?P<status>PASS|FAIL)\s+(?P<file>\S+\.pkt)\s+\((?P<name>.*)\)\s*$"
)
_ORACLE_RE = re.compile(
  r"^\s+(?P<oracle>spec|interpreter|bpf)\s+"
  r"(?P<status>pass|fail|skip|error)"
  r"(?:\s+\[skip:\s*(?P<skip>.*?)\])?"
  r"(?:\s+--\s+(?P<fail>.*))?\s*$"
)
_TOTAL_RE = re.compile(r"^(?P<passed>\d+)/(?P<total>\d+) cases passed\s*$")


def run_corpus(
  fwl_bin: str,
  corpus_dir: Path,
  timeout: float = 600.0,
) -> CorpusVerdict:
  """Run every .pkt under `corpus_dir` and parse the verdict."""
  inv = run_fwl(
    fwl_bin, "test", str(corpus_dir), timeout=timeout
  )
  return _parse_run_output(inv)


def _parse_run_output(inv: FwlInvocation) -> CorpusVerdict:
  """Walk fwl test's text output line-by-line into a CorpusVerdict."""
  cases: list[CaseVerdict] = []
  current_file: str | None = None
  current_name: str | None = None
  current_passed: bool | None = None
  current_oracles: dict[str, str] = {}
  current_details: dict[str, str] = {}
  total = 0
  passed = 0

  def flush():
    if current_file is not None:
      cases.append(CaseVerdict(
        pkt_file=current_file,
        friendly_name=current_name or "",
        passed=bool(current_passed),
        oracles=dict(current_oracles),
        details=dict(current_details),
      ))

  for line in inv.stdout.splitlines():
    h = _HEADER_RE.match(line)
    if h:
      flush()
      current_file = h.group("file")
      current_name = h.group("name")
      current_passed = (h.group("status") == "PASS")
      current_oracles = {}
      current_details = {}
      continue
    o = _ORACLE_RE.match(line)
    if o:
      current_oracles[o.group("oracle")] = o.group("status")
      detail = o.group("skip") or o.group("fail")
      if detail:
        current_details[o.group("oracle")] = detail.strip()
      continue
    t = _TOTAL_RE.match(line)
    if t:
      passed = int(t.group("passed"))
      total = int(t.group("total"))

  flush()
  return CorpusVerdict(
    cases=cases, total=total, passed=passed, invocation=inv
  )
