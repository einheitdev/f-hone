"""Oracle-divergence discovery strategy.

Generate random-ish (program, packet) pairs and run them through the
interpreter and the BPF runtime. Disagreement between the two
oracles is a real bug — the spec is ambiguous about it, the
implementations chose differently.

This strategy doesn't compute an "expected" action; it relies on the
two oracles being independent. They should agree for any well-formed
program and packet; if they don't, that's the find.

Programs are generated from a small seed of templates; packets from
the same builder mini-language fwl uses. Seeded RNG keeps the same
--seed reproducible.
"""
from __future__ import annotations
import random
from typing import Iterable

from .common import Candidate, slug


_PROTOS = ("tcp", "udp", "icmp")
_PORTS = (0, 22, 53, 80, 443, 1024, 8080, 32768, 65535)
_IPS = (
  "1.1.1.1", "10.0.0.1", "172.16.5.5", "192.168.1.1",
  "8.8.8.8", "0.0.0.0", "255.255.255.255",
)
_CIDR_BITS = (8, 16, 24, 32, 0, 1, 31)


_PROGRAM_TEMPLATES = (
  # Simple proto match
  ("@xdp(eth0)\n{action} if pkt.proto == {proto}\ndefault {default}",
   ("action", "proto", "default")),
  # Proto + dst_port
  ("@xdp(eth0)\n{action} if pkt.proto == tcp and pkt.dst_port == {port}\n"
   "default {default}",
   ("action", "port", "default")),
  # Proto + dst_port range
  ("@xdp(eth0)\n{action} if pkt.proto == tcp and "
   "pkt.dst_port in {lo}..{hi}\ndefault {default}",
   ("action", "lo", "hi", "default")),
  # CIDR match
  ("@xdp(eth0)\n{action} if pkt.src_ip in {ip}/{bits}\ndefault {default}",
   ("action", "ip", "bits", "default")),
  # tcp.syn + ack composition
  ("@xdp(eth0)\n{action} if pkt.proto == tcp and pkt.tcp.syn "
   "and not pkt.tcp.ack\ndefault {default}",
   ("action", "default")),
  # nested or
  ("@xdp(eth0)\n{action} if (pkt.proto == tcp or pkt.proto == udp) "
   "and pkt.dst_port == {port}\ndefault {default}",
   ("action", "port", "default")),
)


def _gen_program(rng: random.Random) -> tuple[str, dict]:
  """Pick a template, fill placeholders with random-ish values."""
  template, params = rng.choice(_PROGRAM_TEMPLATES)
  values = {
    "action": rng.choice(("drop", "allow")),
    "default": rng.choice(("drop", "allow")),
    "proto": rng.choice(_PROTOS),
    "port": rng.choice(_PORTS),
    "ip": rng.choice(_IPS).rsplit(".", 1)[0] + ".0",
    "bits": rng.choice(_CIDR_BITS),
  }
  if "lo" in params:
    a, b = sorted(rng.sample(_PORTS, 2))
    values["lo"] = a
    values["hi"] = b
  filled = template.format(**values)
  return filled, values


def _gen_packet_builder(rng: random.Random) -> str:
  """Generate a builder expression for one of tcp/udp/icmp."""
  proto = rng.choice(_PROTOS)
  src_ip = rng.choice(_IPS)
  dst_ip = rng.choice(_IPS)
  if proto == "tcp":
    return (
      f"tcp(src_ip=\"{src_ip}\", dst_ip=\"{dst_ip}\", "
      f"src_port={rng.choice(_PORTS)}, "
      f"dst_port={rng.choice(_PORTS)}, "
      f"syn={'true' if rng.random() < 0.5 else 'false'}, "
      f"ack={'true' if rng.random() < 0.5 else 'false'})"
    )
  if proto == "udp":
    return (
      f"udp(src_ip=\"{src_ip}\", dst_ip=\"{dst_ip}\", "
      f"src_port={rng.choice(_PORTS)}, "
      f"dst_port={rng.choice(_PORTS)})"
    )
  return f"icmp(src_ip=\"{src_ip}\", dst_ip=\"{dst_ip}\")"


def generate(
  target=None, count: int = 200, seed: int = 0
) -> Iterable[Candidate]:
  """Generate `count` random (program, packet) pairs.

  expected_action is set to None — we don't claim an answer. The
  runner compares the two oracles directly; agreement is the success
  case, divergence is the find.
  """
  rng = random.Random(seed)
  for i in range(count):
    fw, _ = _gen_program(rng)
    builder = _gen_packet_builder(rng)
    name = slug(f"div_{i:04d}_{builder.split('(')[0]}")
    body = (
      f"name: \"oracle divergence probe {i}\"\n"
      f"source_fw: |\n"
      + "\n".join("  " + line for line in fw.splitlines())
      + "\n\n"
      f"test_packet:\n  builder: {builder}\n\n"
      f"expected:\n  compiles: true\n  bpf_action: allow\n"
    )
    # We set a placeholder expected_action; the strategy runner will
    # ignore it and instead compare oracles directly.
    yield Candidate(
      name=name,
      fw_source=fw,
      pkt_yaml=body,
      expected_action=None,
      rationale=(
        f"random program/packet pair (seed={seed}, i={i}); "
        f"interpreter and bpf must agree"
      ),
      tags=["oracle-divergence"],
    )
