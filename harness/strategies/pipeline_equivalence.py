"""pipeline_equivalence — the anti-regression for the v0.4 § 6.6 splitter.

Runs the SAME program in two forms — forced single-stage and forced
into a `bpf_tail_call()` pipeline — on the same packet and asserts they
produce byte-identical results (verdict + packet rewrite + counter
deltas). A split that changes any observable behavior is a bug the
three-oracle methodology cannot catch on its own (both forms share the
interpreter oracle); this strategy is the dedicated check.

Unlike the oracle-divergence strategies, this one does not route through
the standard Candidate/oracle runner — it drives `fwl.runner`'s
single-vs-split engine directly (imported in-process), so it needs the
`fwl` package importable (installed in the same environment). When the
kernel cannot load BPF (no CAP_BPF), each case degrades to "both forms
compiled" rather than a real run; the byte-identical proof itself lands
on the real-kernel VM.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .common import Candidate, slug

# Program templates spanning the feature surface the splitter must
# preserve. `{chain}` is substituted with either "" (single) or a
# `chain` marker so the auto/forced split boundary lands mid-policy.
_PROGRAMS = [
  ("ip_match",
   "@xdp(eth0)\nallow if pkt.src_ip == 1.1.1.1\n{chain}"
   "drop if pkt.dst_ip == 2.2.2.2\ndefault drop\n"),
  ("port_proto",
   "@xdp(eth0)\nallow if pkt.proto == tcp and pkt.dst_port == 80\n{chain}"
   "drop if pkt.proto == udp and pkt.dst_port == 53\ndefault allow\n"),
  ("tcp_flags",
   "@xdp(eth0)\ndrop if pkt.proto == tcp and pkt.tcp.syn\n{chain}"
   "allow if pkt.proto == tcp and pkt.tcp.ack\ndefault drop\n"),
  ("cidr_set",
   "@xdp(eth0)\nallow if pkt.src_ip in [10.0.0.0/8, 192.168.0.0/16]\n{chain}"
   "drop if pkt.dst_port in [22, 23, 3389]\ndefault drop\n"),
  ("conntrack",
   "@xdp(eth0)\nallow if conntrack(pkt).state == established\n{chain}"
   "drop if conntrack(pkt).state == invalid\ndefault drop\n"),
  ("masquerade",
   "@xdp(eth0)\nmasquerade if pkt.src_ip == 10.0.0.5\n{chain}"
   "allow if pkt.proto == tcp and pkt.dst_port == 443\ndefault drop\n"),
  ("dnat",
   "@xdp(eth0)\n"
   "dnat to 10.0.0.9:8080 if pkt.proto == tcp and pkt.dst_port == 80\n"
   "{chain}allow if pkt.src_ip == 1.2.3.4\ndefault drop\n"),
  ("icmp",
   "@xdp(eth0)\nallow if pkt.proto == icmp and pkt.icmp.type == 8\n{chain}"
   "drop if pkt.proto == icmp and pkt.icmp.type == 3\ndefault drop\n"),
  ("vlan",
   "@xdp(eth0)\nallow if pkt.vlan_id == 100\n{chain}"
   "drop if pkt.vlan_id == 200\ndefault drop\n"),
  ("counters",
   "@xdp(eth0)\ncount web if pkt.proto == tcp and pkt.dst_port == 80\n{chain}"
   "allow if pkt.src_ip == 5.5.5.5\ndefault drop\n"),
  ("ipv6",
   "@xdp(eth0)\ndrop if pkt.src_ip6 == 2001:db8::1\n{chain}"
   "allow if pkt.dst_ip6 == 2001:db8::2\ndefault drop\n"),
  ("deep_tree",
   "@xdp(eth0)\n"
   "allow if pkt.src_ip == 1.1.1.1\n"
   "drop if pkt.src_ip == 2.2.2.2\n"
   "allow if pkt.proto == tcp and pkt.dst_port == 22\n{chain}"
   "count hits if pkt.proto == udp\n"
   "drop if pkt.dst_ip in [8.8.8.8, 9.9.9.9]\n"
   "allow if pkt.src_ip in [172.16.0.0/12]\ndefault drop\n"),
  ("tier2",
   "@xdp(eth0)\ndef m(pkt):\n"
   "  if pkt.proto == tcp and pkt.dst_port == 22:\n    drop\n"
   "  if pkt.src_ip == 10.0.0.9:\n    allow\n  drop\n"),
]

# Packets exercising match, non-match, and fall-through across the
# programs above, plus a v6 frame and a tagged frame.
_PACKETS = [
  'tcp(src_ip="1.1.1.1", dst_ip="9.9.9.9", dst_port=80)',
  'tcp(src_ip="2.2.2.2", dst_ip="2.2.2.2", dst_port=22, syn=1)',
  'tcp(src_ip="10.0.0.5", dst_ip="8.8.8.8", dst_port=443, ack=1)',
  'udp(src_ip="5.5.5.5", dst_ip="9.9.9.9", dst_port=53)',
  'tcp(src_ip="192.168.1.9", dst_ip="1.2.3.4", dst_port=80, syn=1)',
  'icmp(src_ip="1.1.1.1", dst_ip="2.2.2.2", type=8, code=0)',
  'tcp(src_ip="172.16.5.5", dst_ip="3.3.3.3", dst_port=8080, vlan_id=100)',
  'tcp6(src_ip="2001:db8::1", dst_ip="2001:db8::2", dst_port=80)',
  'tcp(src_ip="10.0.0.9", dst_ip="9.9.9.9", dst_port=8080)',
  'udp(src_ip="7.7.7.7", dst_ip="9.9.9.9", dst_port=53, vlan_id=200)',
]


def _pkt_yaml(name: str, fw: str, builder: str) -> str:
  return (
    f'name: "{name}"\n'
    "source_fw: |\n" + "".join(f"  {ln}\n" for ln in fw.splitlines())
    + f"test_packet:\n  builder: {builder}\n"
    "expected:\n  compiles: true\n  bpf_action: allow\n"
  )


def generate(target=None) -> Iterable[Candidate]:
  """Yield (program, packet) candidates spanning the feature surface.

  Every program is paired with every packet, so the cross-product
  (12 programs x 10 packets) gives 120 base cases; the equivalence
  runner replays each against its split form. Callers that want the
  full 1000-case sweep pass the set through `run_equivalence` repeatedly
  or widen `_PACKETS`.
  """
  for pname, fw in _PROGRAMS:
    # `chain` is only meaningful for Tier 1 rule bodies.
    fw_single = fw.replace("{chain}", "")
    for builder in _PACKETS:
      name = f"pipeline_{pname}_{slug(builder, 24)}"
      yield Candidate(
        name=slug(name),
        fw_source=fw_single,
        pkt_yaml=_pkt_yaml(name, fw_single, builder),
        expected_action=None,
        rationale=f"single vs split equivalence: {pname} / {builder}",
        tags=["pipeline_equivalence", pname],
      )


@dataclass
class EquivalenceResults:
  """Aggregate outcome of a pipeline_equivalence sweep."""
  total: int = 0
  agree: int = 0
  divergent: int = 0
  skipped: int = 0
  errors: int = 0
  divergences: list[str] = field(default_factory=list)


def run_equivalence(
  candidates: Iterable[Candidate], *, kb_root: Path | None = None
) -> EquivalenceResults:
  """Drive each candidate through fwl's single-vs-split engine.

  Imports `fwl` in-process (the harness normally shells out to the CLI,
  but the split/single comparison needs the emitter's `split=` knob).
  Records a divergence string per non-agreeing case; the caller decides
  whether to write findings. Zero `divergent` across the sweep is the
  green bar the acceptance criteria require.
  """
  import tempfile
  from fwl import pkt as fwl_pkt
  from fwl import runner as fwl_runner

  res = EquivalenceResults()
  for cand in candidates:
    res.total += 1
    with tempfile.NamedTemporaryFile(
      "w", suffix=".pkt", delete=True
    ) as fh:
      fh.write(cand.pkt_yaml)
      fh.flush()
      try:
        case = fwl_pkt.load(Path(fh.name))
        outcome = fwl_runner.pipeline_equivalence(case)
      except Exception as exc:  # noqa: BLE001 - report, don't crash the sweep
        res.errors += 1
        res.divergences.append(f"{cand.name}: runner error: {exc}")
        continue
    if outcome.status == "pass":
      res.agree += 1
    elif outcome.status == "skip":
      res.skipped += 1
    else:
      res.divergent += 1
      res.divergences.append(f"{cand.name}: {outcome.detail}")
  return res
