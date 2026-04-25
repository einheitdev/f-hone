"""Strategy runner: Candidate -> Probe -> Finding/corpus IO.

Takes an iterable of Candidates (from any strategy), writes each to a
temp pair of (.fw + .pkt) files, runs both oracles, compares the
results to expected, and either:

  - Records a Probe.AGREE if all oracles match expected (or each
    other when expected is None).
  - Records a Probe.ORACLE_DIVERGENCE and writes a Finding +
    corpus entry to the kb.
  - Records a Probe.COMPILE_FAILED if the program didn't even
    compile (sometimes intentional, sometimes a strategy bug).
  - Records a Probe.RUNNER_ERROR for surprises.

The runner is dumb on purpose — strategies decide what's interesting
to test; the runner just executes and classifies.
"""
from __future__ import annotations
import re
import shutil
import tempfile
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Iterable

from ..knowledge.types import Finding, Layer, Severity
from ..knowledge.writer import write_finding
from ..oracles.bpf_runner import CaseVerdict, run_corpus
from ..oracles.fwl_subprocess import FwlInvocation
from .common import Candidate, Probe, Verdict


@dataclass
class StrategyResults:
  """Aggregate outcome of running a batch of Candidates."""
  total: int = 0
  agree: int = 0
  divergent: int = 0
  compile_failed: int = 0
  runner_error: int = 0
  findings_written: list[Path] = None  # type: ignore[assignment]

  def __post_init__(self):
    if self.findings_written is None:
      self.findings_written = []


def run_strategy(
  candidates: Iterable[Candidate],
  *,
  fwl_bin: str,
  kb_root: Path,
  strategy_name: str,
  layer: Layer = Layer.COMPILER,
) -> tuple[list[Probe], StrategyResults]:
  """Execute every Candidate, classify, write findings to kb_root."""
  probes: list[Probe] = []
  results = StrategyResults()

  cands = list(candidates)
  if not cands:
    return probes, results
  results.total = len(cands)

  with tempfile.TemporaryDirectory(prefix="hone-fuzz-") as tmp:
    tmpdir = Path(tmp)
    # Materialize each candidate as a .pkt file. The .fw source is
    # already inlined in the YAML body, so the runner only needs the
    # .pkt files.
    name_to_cand: dict[str, Candidate] = {}
    for cand in cands:
      pkt_path = tmpdir / f"{cand.name}.pkt"
      pkt_path.write_text(cand.pkt_yaml, encoding="utf-8")
      name_to_cand[pkt_path.name] = cand

    # One `fwl test` invocation drains the whole batch — much faster
    # than per-case subprocess startup.
    verdict = run_corpus(fwl_bin, tmpdir, timeout=600.0)

    for case in verdict.cases:
      cand = name_to_cand.get(case.pkt_file)
      if cand is None:
        continue
      probe = _classify(cand, case, verdict.invocation)
      probes.append(probe)
      if probe.verdict == Verdict.AGREE:
        results.agree += 1
      elif probe.verdict == Verdict.ORACLE_DIVERGENCE:
        results.divergent += 1
        finding_path = _write_divergence_finding(
          probe, kb_root, strategy_name, layer
        )
        results.findings_written.append(finding_path)
        # Promote the .pkt into the kb's corpus so the next regression
        # run picks it up automatically.
        _promote_to_corpus(pkt_path=tmpdir / case.pkt_file,
                           kb_root=kb_root, finding_id=cand.name)
      elif probe.verdict == Verdict.COMPILE_FAILED:
        results.compile_failed += 1
      else:
        results.runner_error += 1

  return probes, results


_DETAIL_GOT = re.compile(r"got\s+(?P<got>XDP_PASS|XDP_DROP)")


def _extract_actual(detail: str) -> str | None:
  """Pull the 'got XDP_X' value out of an oracle's failure message."""
  if not detail:
    return None
  m = _DETAIL_GOT.search(detail)
  return m.group("got") if m else None


def _classify(
  cand: Candidate,
  case: CaseVerdict,
  inv: FwlInvocation,
) -> Probe:
  """Map fwl test's per-case verdict to a Probe.

  The interesting distinction: when both interpreter and bpf actually
  ran and *agreed with each other* but neither matched the .pkt's
  expected action, that's NOT a compiler bug — it's a strategy bug
  (wrong expected value) or a spec/strategy drift. Real compiler
  bugs only show up when the two oracles disagree with each other.
  """
  interp_status = case.oracles.get("interpreter")
  bpf_status = case.oracles.get("bpf")
  interp_got = _extract_actual(case.details.get("interpreter", ""))
  bpf_got = _extract_actual(case.details.get("bpf", ""))

  # All oracles passed (or the only failures were skips).
  if case.passed:
    return Probe(
      candidate=cand,
      verdict=Verdict.AGREE,
      interpreter_action=cand.expected_action,
      bpf_action=cand.expected_action,
    )

  # Compile failure: distinct from oracle disagreement so the runner
  # can flag a strategy-generated program that doesn't even compile
  # without mistaking it for a finding.
  if (
    interp_status in ("error", "fail")
    and "compile" in case.details.get("interpreter", "").lower()
  ):
    return Probe(
      candidate=cand,
      verdict=Verdict.COMPILE_FAILED,
      interpreter_action=None,
      bpf_action=None,
      detail=case.details.get("interpreter", ""),
    )

  # Both oracles ran and both reported "got X" — the real test:
  # do they agree with EACH OTHER?
  if interp_got and bpf_got:
    if interp_got == bpf_got:
      # Oracles agreed; the strategy's expected was wrong. Bad test,
      # not a compiler bug.
      return Probe(
        candidate=cand,
        verdict=Verdict.RUNNER_ERROR,
        interpreter_action=interp_got,
        bpf_action=bpf_got,
        detail=(
          f"strategy expected {cand.expected_action} but both oracles "
          f"returned {interp_got} — strategy bug, not compiler bug"
        ),
      )
    # Oracles disagreed with each other — real compiler bug.
    return Probe(
      candidate=cand,
      verdict=Verdict.ORACLE_DIVERGENCE,
      interpreter_action=interp_got,
      bpf_action=bpf_got,
      detail=(
        f"interpreter={interp_got} bpf={bpf_got} "
        f"expected={cand.expected_action}"
      ),
    )

  # One oracle failed/erred and the other skipped — partial signal.
  # We can't conclude divergence without seeing both. Surface it so
  # someone can rerun with the missing oracle available.
  if (
    interp_status in ("fail", "error")
    or bpf_status in ("fail", "error")
  ):
    return Probe(
      candidate=cand,
      verdict=Verdict.RUNNER_ERROR,
      interpreter_action=interp_got,
      bpf_action=bpf_got,
      detail=(
        f"only one oracle ran; cannot conclude divergence "
        f"(interpreter={interp_status}, bpf={bpf_status})"
      ),
    )

  return Probe(
    candidate=cand,
    verdict=Verdict.RUNNER_ERROR,
    interpreter_action=interp_status,
    bpf_action=bpf_status,
    detail=f"unclassified: {case.oracles}",
  )


def _write_divergence_finding(
  probe: Probe,
  kb_root: Path,
  strategy_name: str,
  layer: Layer,
) -> Path:
  """Materialize one divergence as a Finding in the kb."""
  cand = probe.candidate
  today = date.today()
  finding_id = f"{today.isoformat()}-{cand.name}"
  body_md = f"""## Root Cause
Found by `hone fuzz {strategy_name}`. Two oracles disagreed when run
through `fwl test`. The interpreter and the compiled BPF should
produce the same XDP action for any well-formed packet; they did not.

## Strategy Rationale
{cand.rationale}

## Test Source
```
{cand.fw_source}
```

## Test Packet
{cand.pkt_yaml}

## Oracle Outcome
- interpreter status: {probe.interpreter_action}
- bpf status: {probe.bpf_action}
- detail: {probe.detail}

## Next Steps
- Reproduce: `fwl test corpus/{finding_id}.pkt`
- Inspect the emitted BPF C: `fwl compile <fw_source>`
- Compare against the interpreter: `fwl interpret`
- Decide: compiler bug (most likely) vs interpreter bug vs spec gap.
"""
  finding = Finding(
    id=finding_id,
    summary=cand.rationale or "oracle divergence",
    body=body_md,
    pattern_tags=cand.tags,
    severity=Severity.MEDIUM,
    layer=layer,
    pkt_path=f"corpus/{finding_id}.pkt",
    created=today,
  )
  return write_finding(finding, kb_root)


def _promote_to_corpus(
  pkt_path: Path, kb_root: Path, finding_id: str
) -> Path:
  """Copy a divergent .pkt into <kb>/corpus/ under the finding's id."""
  today = date.today()
  dest_dir = kb_root / "corpus" / "from_fuzz" / today.isoformat()
  dest_dir.mkdir(parents=True, exist_ok=True)
  dest = dest_dir / f"{today.isoformat()}-{finding_id}.pkt"
  shutil.copy(pkt_path, dest)
  return dest
