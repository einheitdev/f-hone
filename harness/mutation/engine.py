"""Mutator: take a (.fw, .pkt) PoC and emit a fan-out of related cases.

Mutation strategies:

  - port_shift     dst_port → ±1, 0, 65535, common service ports
  - src_port_shift src_port likewise
  - proto_swap     tcp ↔ udp (where applicable)
  - src_ip_octet   bump the last octet of src_ip by ±1
  - tcp_flags      toggle syn/ack one at a time
  - threshold_bump rate_limit(N) → rate_limit(N±1, N+10) in the
                   .fw program (catches off-by-one in the gate)

Each mutant materialises as a temp .fw + .pkt pair, runs through the
existing oracle pipeline (interpreter + clang-compile, plus
BPF_PROG_RUN when available), and is classified the same way the
fuzzer's strategy runner classifies its candidates: oracles
disagreeing on the same packet => divergent => write a new finding.

Mutants where the oracles agree on a different action than the
parent are not findings — they map the BOUNDARY of the parent bug.
We still copy them under <kb>/corpus/from_mutation/ so future hunts
have richer test data.
"""
from __future__ import annotations
import re
import shutil
import tempfile
from datetime import date
from pathlib import Path
from typing import Iterable

import yaml

from ..knowledge.reader import read_finding
from ..knowledge.types import Finding, Layer, Severity
from ..knowledge.writer import write_finding
from ..oracles.bpf_runner import run_corpus
from ..strategies.common import slug
from .types import Mutant, MutationOutcome, MutationResult


_BUILDER_RE = re.compile(
  r"^\s*builder:\s*(?P<proto>tcp|udp|icmp)\((?P<args>.*)\)\s*$",
  re.MULTILINE,
)
_RATE_LIMIT_RE = re.compile(
  r"rate_limit\(\s*(?P<n>\d+)\s*,\s*per\s*=\s*(?P<field>\w+)\s*\)"
)


def _parse_builder_line(pkt_yaml: str) -> tuple[str, dict[str, str]] | None:
  """Pull the proto + arg dict out of a `.pkt`'s `builder:` line.

  We work textually so a malformed YAML doesn't kill the mutator —
  if there's no parseable builder, the caller falls back to identity.
  """
  m = _BUILDER_RE.search(pkt_yaml)
  if not m:
    return None
  proto = m.group("proto")
  args: dict[str, str] = {}
  for raw in m.group("args").split(","):
    raw = raw.strip()
    if not raw or "=" not in raw:
      continue
    k, v = raw.split("=", 1)
    args[k.strip()] = v.strip()
  return proto, args


def _format_builder(proto: str, args: dict[str, str]) -> str:
  """Re-render a builder dict back to `proto(k1=v1, k2=v2)` form."""
  body = ", ".join(f"{k}={v}" for k, v in args.items())
  return f"{proto}({body})"


def _swap_builder(
  pkt_yaml: str, new_proto: str, new_args: dict[str, str],
) -> str:
  """Replace the builder line in a .pkt YAML with a new (proto, args)."""
  return _BUILDER_RE.sub(
    f"  builder: {_format_builder(new_proto, new_args)}",
    pkt_yaml,
    count=1,
  )


def _strip_state(pkt_yaml: str) -> str:
  """Drop the `state:` block from a .pkt — used when a mutation
  changes the protocol or src_ip enough that prior state would no
  longer apply (and would confuse the bucket lookup)."""
  doc = yaml.safe_load(pkt_yaml)
  doc.pop("state", None)
  return yaml.safe_dump(doc, sort_keys=False)


def _port_neighbors(value: int) -> list[int]:
  """Boundary-flavoured port neighbours, deduped."""
  cands = {value - 1, value + 1, 0, 1, 65535, 53, 80, 443, 22}
  cands.discard(value)
  return sorted(p for p in cands if 0 <= p <= 65535)


def _src_ip_neighbors(addr: str) -> list[str]:
  """Bump the last octet of a dotted-quad ±1 (clipped to 0..255)."""
  if not isinstance(addr, str):
    return []
  parts = addr.strip('"').split(".")
  if len(parts) != 4:
    return []
  try:
    last = int(parts[3])
  except ValueError:
    return []
  out: list[str] = []
  for delta in (-1, 1):
    new = last + delta
    if 0 <= new <= 255:
      out.append(f'"{parts[0]}.{parts[1]}.{parts[2]}.{new}"')
  return out


def _gen_port_mutants(
  parent_name: str, fw: str, pkt: str,
  proto: str, args: dict[str, str], parent_id: str | None,
) -> Iterable[Mutant]:
  """dst_port and src_port boundary neighbours."""
  for key in ("dst_port", "src_port"):
    raw = args.get(key)
    if raw is None or not raw.isdigit():
      continue
    base = int(raw)
    for nv in _port_neighbors(base):
      new_args = dict(args)
      new_args[key] = str(nv)
      yield Mutant(
        name=f"{parent_name}__{key}_{nv}",
        fw_source=fw,
        pkt_yaml=_swap_builder(pkt, proto, new_args),
        rationale=f"port shift: {key}={base} → {nv}",
        mutation="port_shift",
        parent_finding_id=parent_id,
        tags=["mutation", "port-shift"],
      )


def _gen_proto_swap_mutants(
  parent_name: str, fw: str, pkt: str,
  proto: str, args: dict[str, str], parent_id: str | None,
) -> Iterable[Mutant]:
  """Swap TCP↔UDP keeping the same ports/IPs; drop tcp-flag args
  when leaving TCP."""
  if proto not in ("tcp", "udp"):
    return
  other = "udp" if proto == "tcp" else "tcp"
  new_args = {
    k: v for k, v in args.items()
    if not k.startswith("syn") and not k.startswith("ack")
    and not k.startswith("fin") and not k.startswith("rst")
  }
  yield Mutant(
    name=f"{parent_name}__proto_{other}",
    fw_source=fw,
    pkt_yaml=_strip_state(_swap_builder(pkt, other, new_args)),
    rationale=f"proto swap: {proto} → {other}",
    mutation="proto_swap",
    parent_finding_id=parent_id,
    tags=["mutation", "proto-swap"],
  )


def _gen_src_ip_mutants(
  parent_name: str, fw: str, pkt: str,
  proto: str, args: dict[str, str], parent_id: str | None,
) -> Iterable[Mutant]:
  """Bump src_ip's last octet ±1 — catches edge of CIDR / per-bucket
  isolation."""
  raw = args.get("src_ip")
  if raw is None:
    return
  for new in _src_ip_neighbors(raw):
    new_args = dict(args)
    new_args["src_ip"] = new
    # Drop state — neighbour IP has its own bucket.
    yield Mutant(
      name=f"{parent_name}__src_ip_{new.strip(chr(34)).replace('.', '_')}",
      fw_source=fw,
      pkt_yaml=_strip_state(_swap_builder(pkt, proto, new_args)),
      rationale=f"src_ip neighbour: {raw} → {new}",
      mutation="src_ip_octet",
      parent_finding_id=parent_id,
      tags=["mutation", "src-ip-bump"],
    )


def _gen_tcp_flag_mutants(
  parent_name: str, fw: str, pkt: str,
  proto: str, args: dict[str, str], parent_id: str | None,
) -> Iterable[Mutant]:
  """Toggle SYN and ACK individually (TCP only)."""
  if proto != "tcp":
    return
  for flag in ("syn", "ack"):
    cur = args.get(flag, "false").lower()
    new_val = "false" if cur == "true" else "true"
    new_args = dict(args)
    new_args[flag] = new_val
    yield Mutant(
      name=f"{parent_name}__{flag}_{new_val}",
      fw_source=fw,
      pkt_yaml=_swap_builder(pkt, proto, new_args),
      rationale=f"tcp flag toggle: {flag}={cur} → {new_val}",
      mutation="tcp_flag_toggle",
      parent_finding_id=parent_id,
      tags=["mutation", "tcp-flags"],
    )


def _gen_threshold_mutants(
  parent_name: str, fw: str, pkt: str,
  proto: str, args: dict[str, str], parent_id: str | None,
) -> Iterable[Mutant]:
  """Bump every rate_limit threshold in the source ±1 and +10. Catches
  off-by-one at the firing predicate."""
  for m in _RATE_LIMIT_RE.finditer(fw):
    n = int(m.group("n"))
    for delta in (-1, 1, 10):
      new_n = n + delta
      if new_n <= 0:
        continue
      new_fw = (
        fw[:m.start()]
        + f"rate_limit({new_n}, per={m.group('field')})"
        + fw[m.end():]
      )
      yield Mutant(
        name=f"{parent_name}__threshold_{n}_to_{new_n}",
        fw_source=new_fw,
        pkt_yaml=pkt,
        rationale=f"rate_limit threshold shift: {n} → {new_n}",
        mutation="threshold_bump",
        parent_finding_id=parent_id,
        tags=["mutation", "threshold-bump"],
      )


def mutate_pkt(
  fw_source: str,
  pkt_yaml: str,
  parent_name: str,
  parent_id: str | None = None,
) -> list[Mutant]:
  """Generate every mutant for one (fw, pkt) PoC."""
  parsed = _parse_builder_line(pkt_yaml)
  mutants: list[Mutant] = []
  if parsed is not None:
    proto, args = parsed
    mutants.extend(_gen_port_mutants(
      parent_name, fw_source, pkt_yaml, proto, args, parent_id,
    ))
    mutants.extend(_gen_proto_swap_mutants(
      parent_name, fw_source, pkt_yaml, proto, args, parent_id,
    ))
    mutants.extend(_gen_src_ip_mutants(
      parent_name, fw_source, pkt_yaml, proto, args, parent_id,
    ))
    mutants.extend(_gen_tcp_flag_mutants(
      parent_name, fw_source, pkt_yaml, proto, args, parent_id,
    ))
  # Threshold mutants don't depend on the builder; safe to run even
  # if we couldn't parse the packet.
  mutants.extend(_gen_threshold_mutants(
    parent_name, fw_source, pkt_yaml, "", {}, parent_id,
  ))
  return mutants


def _materialize(
  mutants: list[Mutant], tmpdir: Path,
) -> dict[str, Mutant]:
  """Write each mutant to a .pkt under tmpdir; return filename → mutant."""
  name_to_mut: dict[str, Mutant] = {}
  for mut in mutants:
    pkt_path = tmpdir / f"{mut.name}.pkt"
    yaml_with_src = _ensure_source_fw(mut.pkt_yaml, mut.fw_source)
    pkt_path.write_text(yaml_with_src, encoding="utf-8")
    name_to_mut[pkt_path.name] = mut
  return name_to_mut


_SOURCE_FW_RE = re.compile(r"^source_fw:\s*\|", re.MULTILINE)


def _ensure_source_fw(pkt_yaml: str, fw_source: str) -> str:
  """Replace (or insert) the source_fw block in a .pkt YAML."""
  doc = yaml.safe_load(pkt_yaml) or {}
  doc["source_fw"] = fw_source
  # Round-trip through yaml so multi-line .fw bodies stay readable.
  return yaml.safe_dump(doc, sort_keys=False, width=10_000)


_DETAIL_GOT = re.compile(r"got\s+(?P<got>XDP_PASS|XDP_DROP)")


def _classify(case, mut: Mutant) -> MutationOutcome:
  """Same divergence logic as strategies/runner.py: oracles must
  disagree on the same packet for a mutant to count as a finding."""
  interp_status = case.oracles.get("interpreter")
  if interp_status in ("error", "fail") and "compile" in case.details.get(
    "interpreter", ""
  ).lower():
    return MutationOutcome.COMPILE_FAILED
  interp_got = _extract_action(case.details.get("interpreter", ""))
  bpf_got = _extract_action(case.details.get("bpf", ""))
  if interp_got and bpf_got:
    return (
      MutationOutcome.DIVERGENT if interp_got != bpf_got
      else MutationOutcome.AGREE
    )
  if case.passed:
    return MutationOutcome.AGREE
  return MutationOutcome.RUNNER_ERROR


def _extract_action(detail: str) -> str | None:
  if not detail:
    return None
  m = _DETAIL_GOT.search(detail)
  return m.group("got") if m else None


def _load_pkts_from_path(
  kb_root: Path, pkt_path: str | None,
) -> list[tuple[str, str]]:
  """Resolve a finding's `pkt_path` frontmatter field to a list of
  (filename, raw .pkt yaml) pairs.

  pkt_path may be a single .pkt file or a directory containing
  multiple .pkts. Relative paths resolve against the kb root.
  Returns [] when pkt_path is missing or unresolvable.
  """
  if not pkt_path:
    return []
  p = (kb_root / pkt_path).resolve()
  if p.is_file():
    return [(p.stem, p.read_text(encoding="utf-8"))]
  if p.is_dir():
    return [
      (f.stem, f.read_text(encoding="utf-8"))
      for f in sorted(p.glob("*.pkt"))
    ]
  return []


def _extract_source_fw(pkt_yaml: str) -> str | None:
  """Pull the `source_fw:` block out of a .pkt yaml."""
  doc = yaml.safe_load(pkt_yaml) or {}
  src = doc.get("source_fw")
  return src if isinstance(src, str) else None


def mutate_finding(
  finding_id: str,
  kb_root: Path,
  fwl_bin: str,
  timeout: float = 600.0,
) -> MutationResult:
  """Load a finding, mutate its embedded (.fw, .pkt) PoC, and run all
  mutants through the oracle pipeline. Mutants that produce a fresh
  oracle divergence get written as related findings; agreed mutants
  go into <kb>/corpus/from_mutation/ so the next regression sweep
  picks them up.

  PoC resolution order:
    1. Inline ## Test Source (fenced) + ## Test Packet (YAML) blocks
       in the finding body.
    2. Falls back to the frontmatter `pkt_path` — single .pkt or a
       directory of .pkts. Each .pkt provides its own `source_fw:`.
  """
  kb_root = kb_root.resolve()
  finding_path = _resolve_finding(kb_root, finding_id)
  parent = read_finding(finding_path)
  pairs: list[tuple[str, str]] = []
  fw, pkt = _extract_poc(parent.body)
  if fw is not None and pkt is not None:
    pairs.append(("inline", _ensure_source_fw(pkt, fw)))
  pairs.extend(_load_pkts_from_path(kb_root, parent.pkt_path))
  if not pairs:
    raise ValueError(
      f"Could not extract a PoC from finding {parent.id}; the body "
      "lacks ## Test Source / ## Test Packet blocks AND the "
      "`pkt_path` frontmatter field is missing or unresolvable."
    )
  mutants: list[Mutant] = []
  for stem, raw_pkt in pairs:
    fw_text = _extract_source_fw(raw_pkt)
    if fw_text is None:
      continue
    mutants.extend(mutate_pkt(
      fw_text, raw_pkt,
      parent_name=f"{parent.id}__{stem}",
      parent_id=parent.id,
    ))
  result = MutationResult(total=len(mutants))
  if not mutants:
    return result
  corpus_dir = (
    kb_root / "corpus" / "from_mutation" / date.today().isoformat()
    / slug(parent.id)
  )
  corpus_dir.mkdir(parents=True, exist_ok=True)
  with tempfile.TemporaryDirectory(prefix="hone-mutate-") as tmp:
    tmpdir = Path(tmp)
    name_to_mut = _materialize(mutants, tmpdir)
    verdict = run_corpus(fwl_bin, tmpdir, timeout=timeout)
    for case in verdict.cases:
      mut = name_to_mut.get(case.pkt_file)
      if mut is None:
        continue
      outcome = _classify(case, mut)
      if outcome == MutationOutcome.DIVERGENT:
        result.divergent += 1
        result.findings_written.append(_write_mutant_finding(
          mut, case, kb_root, parent
        ))
        _promote(tmpdir / case.pkt_file, corpus_dir, mut.name)
        result.mutants_written.append(corpus_dir / f"{mut.name}.pkt")
      elif outcome == MutationOutcome.AGREE:
        result.agree += 1
        _promote(tmpdir / case.pkt_file, corpus_dir, mut.name)
        result.mutants_written.append(corpus_dir / f"{mut.name}.pkt")
      elif outcome == MutationOutcome.COMPILE_FAILED:
        result.compile_failed += 1
      else:
        result.runner_error += 1
  return result


def _resolve_finding(kb_root: Path, finding_id: str) -> Path:
  """Locate a finding markdown file by id (with or without .md)."""
  bare = finding_id.split("/", 1)[1] if "/" in finding_id else finding_id
  for ext in (".md", ""):
    path = kb_root / "findings" / f"{bare}{ext}"
    if path.is_file():
      return path
  raise FileNotFoundError(
    f"finding {finding_id!r} not found under {kb_root}/findings/"
  )


_FENCED_FW = re.compile(
  r"##\s+Test Source\s*\n+```(?:fwl)?\s*\n(?P<fw>.*?)\n```",
  re.DOTALL,
)
_PKT_BLOCK = re.compile(
  r"##\s+Test Packet\s*\n+(?P<pkt>(?:.+\n)+?)(?=\n##\s+|\Z)",
  re.DOTALL,
)


def _extract_poc(body: str) -> tuple[str | None, str | None]:
  """Pull the ## Test Source (fenced .fw) and ## Test Packet (.pkt
  YAML) blocks out of a finding's markdown body."""
  fw_m = _FENCED_FW.search(body)
  pkt_m = _PKT_BLOCK.search(body)
  fw = fw_m.group("fw").strip() if fw_m else None
  pkt = pkt_m.group("pkt").strip() if pkt_m else None
  return fw, pkt


def _write_mutant_finding(
  mut: Mutant, case, kb_root: Path, parent: Finding,
) -> Path:
  """Materialize a divergent mutant as its own finding, related to parent."""
  today = date.today()
  finding_id = f"{today.isoformat()}-mutant-{slug(mut.name, 60)}"
  related = parent.id
  body = f"""## Summary
Oracle divergence on a mutation of finding `{related}` ({mut.mutation}).
{mut.rationale}

## Mutation Strategy
{mut.mutation}: {mut.rationale}

## Test Source
```
{mut.fw_source}
```

## Test Packet
{mut.pkt_yaml}

## Oracle Outcome
- interpreter: {case.details.get("interpreter", "")[:200]}
- bpf:         {case.details.get("bpf", "")[:200]}

## Parent
[finding/{related}](../findings/{related}.md)
"""
  finding = Finding(
    id=finding_id,
    summary=f"mutant of {related}: {mut.rationale}",
    body=body,
    protocols=parent.protocols,
    builtins=parent.builtins,
    severity=Severity.MEDIUM,
    layer=Layer.COMPILER,
    pattern_tags=list(set(parent.pattern_tags + mut.tags)),
    pkt_path=str(
      Path("corpus") / "from_mutation" / today.isoformat()
      / slug(parent.id) / f"{mut.name}.pkt"
    ),
    created=today,
  )
  return write_finding(finding, kb_root)


def _promote(src: Path, dest_dir: Path, name: str) -> Path:
  """Copy a mutant's .pkt into the kb's from_mutation corpus."""
  dest = dest_dir / f"{name}.pkt"
  shutil.copy(src, dest)
  return dest
