"""Cross-program transfer engine.

Builds on `harness/agents/features.py` (which already extracts
surface features for Solr keying) — same primitive, but here we
compare two programs' feature sets to decide whether a finding's
PoC is worth replaying against a candidate.

Match score is Jaccard over the (built-in, protocol, field)
signature plus a structural bonus when both programs use the same
combination of {has_rate_limit, has_default}. Above a threshold
(default 0.5), the candidate is "in scope" — the parent's PoC .pkt
is replayed against the candidate program through both oracles. A
fresh oracle disagreement becomes a related finding; agreement on
the parent's expected outcome is logged but not promoted.
"""
from __future__ import annotations
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import yaml

from ..agents.features import TargetFeatures, extract, extract_from_path
from ..knowledge.reader import read_finding
from ..knowledge.types import Finding, Layer, Severity
from ..knowledge.writer import write_finding
from ..oracles.bpf_runner import run_corpus
from ..strategies.common import slug
from ..mutation.engine import (
  _classify,
  _ensure_source_fw,
  _extract_action,
  _extract_source_fw,
  _load_pkts_from_path,
)
from ..mutation.types import MutationOutcome


@dataclass
class ConstructSignature:
  """Compact representation of a program's testable surface."""
  protocols: frozenset[str] = frozenset()
  builtins: frozenset[str] = frozenset()
  fields: frozenset[str] = frozenset()
  has_rate_limit: bool = False
  has_default: bool = False

  @classmethod
  def from_features(cls, f: TargetFeatures) -> "ConstructSignature":
    return cls(
      protocols=frozenset(f.protocols),
      builtins=frozenset(f.builtins),
      fields=frozenset(f.fields),
      has_rate_limit=f.has_rate_limit,
      has_default=f.has_default,
    )

  def jaccard(self, other: "ConstructSignature") -> float:
    """Jaccard over the union of construct sets, with a small structural
    bonus when both signatures share the same modifier flags."""
    union = (
      (self.protocols | other.protocols)
      | (self.builtins | other.builtins)
      | (self.fields | other.fields)
    )
    if not union:
      return 0.0
    inter = (
      (self.protocols & other.protocols)
      | (self.builtins & other.builtins)
      | (self.fields & other.fields)
    )
    base = len(inter) / len(union)
    bonus = 0.05 * sum([
      self.has_rate_limit == other.has_rate_limit,
      self.has_default == other.has_default,
    ])
    return min(1.0, base + bonus)


@dataclass
class TransferProbe:
  """One (parent_finding, candidate_program) pair we considered."""
  candidate_path: Path
  score: float
  outcome: MutationOutcome | None = None
  finding_path: Path | None = None
  detail: str = ""


@dataclass
class TransferResult:
  """Aggregate outcome of one `hone transfer` invocation."""
  total_candidates: int = 0
  matched: int = 0
  divergent: int = 0
  agreed: int = 0
  skipped_low_score: int = 0
  probes: list[TransferProbe] = field(default_factory=list)
  findings_written: list[Path] = field(default_factory=list)


_FENCED_FW = re.compile(
  r"##\s+Test Source\s*\n+```(?:fwl)?\s*\n(?P<fw>.*?)\n```",
  re.DOTALL,
)
_PKT_BLOCK = re.compile(
  r"##\s+Test Packet\s*\n+(?P<pkt>(?:.+\n)+?)(?=\n##\s+|\Z)",
  re.DOTALL,
)


def _extract_poc(body: str) -> tuple[str | None, str | None]:
  """Pull (.fw, .pkt) blocks out of a finding's markdown body."""
  fw_m = _FENCED_FW.search(body)
  pkt_m = _PKT_BLOCK.search(body)
  return (
    fw_m.group("fw").strip() if fw_m else None,
    pkt_m.group("pkt").strip() if pkt_m else None,
  )


def signature_of_program(fw_source: str) -> ConstructSignature:
  """Construct signature for an inline .fw program text."""
  return ConstructSignature.from_features(extract(fw_source))


def signature_of_finding(finding: Finding) -> ConstructSignature:
  """Construct signature for the .fw embedded in a finding's body."""
  fw, _ = _extract_poc(finding.body)
  if fw is None:
    raise ValueError(
      f"finding {finding.id!r} has no parseable ## Test Source block"
    )
  return signature_of_program(fw)


def _resolve_finding(kb_root: Path, finding_id: str) -> Path:
  """Locate a finding markdown file by id."""
  bare = finding_id.split("/", 1)[1] if "/" in finding_id else finding_id
  for ext in (".md", ""):
    path = kb_root / "findings" / f"{bare}{ext}"
    if path.is_file():
      return path
  raise FileNotFoundError(
    f"finding {finding_id!r} not found under {kb_root}/findings/"
  )


def _candidate_programs(targets_dir: Path) -> list[Path]:
  """Walk a targets directory for every .fw file."""
  return sorted(targets_dir.rglob("*.fw"))


def _strip_state(pkt_yaml: str) -> str:
  """Drop state from the parent's pkt — buckets in the parent's program
  do not align with the candidate's per-rule indexing."""
  doc = yaml.safe_load(pkt_yaml) or {}
  doc.pop("state", None)
  return yaml.safe_dump(doc, sort_keys=False, width=10_000)


def transfer_finding(
  finding_id: str,
  kb_root: Path,
  targets_dir: Path,
  fwl_bin: str,
  threshold: float = 0.5,
  timeout: float = 600.0,
) -> TransferResult:
  """Replay a finding's PoC packet against every candidate program
  whose signature overlaps the parent's above `threshold`.

  - threshold=0.5 ~= "shares half the constructs". Bumping it
    narrows scope; lowering broadens (and increases false-positive
    runner errors from packets that simply don't apply).
  - State (rate_limit buckets, etc.) is stripped from the parent's
    packet because buckets are keyed by rule index — what is rule 0
    in the parent may be rule 3 in the candidate.
  """
  kb_root = kb_root.resolve()
  parent = read_finding(_resolve_finding(kb_root, finding_id))
  fw_parent, pkt_parent = _extract_poc(parent.body)
  if fw_parent is None or pkt_parent is None:
    # Fall back to pkt_path frontmatter — pick the first .pkt under it.
    pairs = _load_pkts_from_path(kb_root, parent.pkt_path)
    if not pairs:
      raise ValueError(
        f"finding {parent.id!r} has no inline ## Test Source / "
        "## Test Packet AND no resolvable pkt_path frontmatter"
      )
    _, raw = pairs[0]
    fw_parent = _extract_source_fw(raw)
    pkt_parent = raw
    if fw_parent is None:
      raise ValueError(
        f"finding {parent.id!r}'s pkt_path .pkt has no source_fw block"
      )
  parent_sig = signature_of_program(fw_parent)
  pkt_no_state = _strip_state(pkt_parent)

  result = TransferResult()
  candidates: list[tuple[Path, ConstructSignature, float]] = []
  for path in _candidate_programs(targets_dir):
    cand_feats = extract_from_path(path)
    cand_sig = ConstructSignature.from_features(cand_feats)
    score = parent_sig.jaccard(cand_sig)
    candidates.append((path, cand_sig, score))
  result.total_candidates = len(candidates)

  in_scope = [(p, s, sc) for (p, s, sc) in candidates if sc >= threshold]
  result.matched = len(in_scope)
  result.skipped_low_score = result.total_candidates - result.matched
  if not in_scope:
    return result

  with tempfile.TemporaryDirectory(prefix="hone-transfer-") as tmp:
    tmpdir = Path(tmp)
    name_to_pair: dict[str, tuple[Path, str]] = {}
    for path, _sig, _score in in_scope:
      cand_fw = path.read_text(encoding="utf-8")
      pkt_with_src = _ensure_source_fw(pkt_no_state, cand_fw)
      pkt_name = f"transfer__{slug(parent.id)}__{slug(path.stem)}.pkt"
      (tmpdir / pkt_name).write_text(pkt_with_src, encoding="utf-8")
      name_to_pair[pkt_name] = (path, cand_fw)
    verdict = run_corpus(fwl_bin, tmpdir, timeout=timeout)

    today = date.today()
    for case in verdict.cases:
      pair = name_to_pair.get(case.pkt_file)
      if pair is None:
        continue
      cand_path, cand_fw = pair
      probe = TransferProbe(
        candidate_path=cand_path,
        score=parent_sig.jaccard(signature_of_program(cand_fw)),
      )
      probe.outcome = _classify(case, _StubMutant())
      interp_got = _extract_action(case.details.get("interpreter", ""))
      bpf_got = _extract_action(case.details.get("bpf", ""))
      probe.detail = f"interp={interp_got or '?'} bpf={bpf_got or '?'}"
      if probe.outcome == MutationOutcome.DIVERGENT:
        result.divergent += 1
        path_out = _write_transfer_finding(
          parent, cand_path, cand_fw, pkt_no_state, case, kb_root, today,
        )
        probe.finding_path = path_out
        result.findings_written.append(path_out)
        # Promote the .pkt under from_transfer for regression sweeps.
        _promote(
          tmpdir / case.pkt_file, kb_root, parent.id, cand_path, today,
        )
      elif probe.outcome == MutationOutcome.AGREE:
        result.agreed += 1
      result.probes.append(probe)

  return result


class _StubMutant:
  """Placeholder so we can reuse mutation._classify (which only reads
  the case shape, not the mutant's own fields). Cheaper than
  re-deriving the divergence logic."""
  pass


def _write_transfer_finding(
  parent: Finding,
  cand_path: Path,
  cand_fw: str,
  pkt_yaml: str,
  case,
  kb_root: Path,
  today: date,
) -> Path:
  """Materialize a transfer-divergent case as a related finding."""
  finding_id = (
    f"{today.isoformat()}-transfer-{slug(parent.id, 40)}-to-"
    f"{slug(cand_path.stem, 30)}"
  )
  body = f"""## Summary
Replay of finding `{parent.id}`'s PoC against `{cand_path.name}`
produced an oracle divergence — same packet, different program,
oracles disagree on the action.

## Parent
[finding/{parent.id}](../findings/{parent.id}.md)

## Candidate Program
File: `{cand_path}`

```
{cand_fw}
```

## Test Packet (from parent)
{pkt_yaml}

## Oracle Outcome
- interpreter: {case.details.get("interpreter", "")[:200]}
- bpf:         {case.details.get("bpf", "")[:200]}
"""
  finding = Finding(
    id=finding_id,
    summary=(
      f"transfer of {parent.id} → {cand_path.name}: oracle divergence"
    ),
    body=body,
    protocols=parent.protocols,
    builtins=parent.builtins,
    severity=Severity.MEDIUM,
    layer=Layer.COMPILER,
    pattern_tags=list(set(parent.pattern_tags + ["cross-program-transfer"])),
    pkt_path=str(
      Path("corpus") / "from_transfer" / today.isoformat()
      / f"{slug(parent.id, 40)}__{slug(cand_path.stem, 30)}.pkt"
    ),
    created=today,
  )
  return write_finding(finding, kb_root)


def _promote(
  src: Path, kb_root: Path, parent_id: str, cand_path: Path, today: date,
) -> Path:
  """Copy the transfer .pkt into the kb's from_transfer corpus."""
  dest_dir = kb_root / "corpus" / "from_transfer" / today.isoformat()
  dest_dir.mkdir(parents=True, exist_ok=True)
  dest = dest_dir / (
    f"{slug(parent_id, 40)}__{slug(cand_path.stem, 30)}.pkt"
  )
  shutil.copy(src, dest)
  return dest
