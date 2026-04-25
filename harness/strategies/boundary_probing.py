"""Boundary-probing discovery strategy.

Generates deterministic test cases at boundary values of every
language-level integer field: ports (0, 1, 65534, 65535), CIDR
prefixes (0, 1, 31, 32), TCP flags (set + clear combinations),
rate_limit thresholds (1, u32_max). For each, builds a tiny FWL
program that exercises the boundary and a packet that probes it.

No LLM, no API cost. Output is fed to the oracle runner; oracle
disagreement (interpreter vs BPF) becomes a finding.

Boundary value choice rationale: classic off-by-one bugs cluster at
the edges of representable ranges. The 0/1/max-1/max/max+1 set has
been the staple of fuzzers since the 80s for a reason.
"""
from __future__ import annotations
from typing import Iterable

from .common import Candidate, slug


# Port-field boundary tests. Each generates one (program, packet)
# pair where the program drops on a specific port and the packet
# carries that exact port.
_PORT_BOUNDARIES = (0, 1, 1023, 1024, 32767, 32768, 65534, 65535)

# CIDR prefix boundary tests. /0 matches everything; /32 matches one.
_CIDR_BOUNDARIES = (0, 1, 7, 8, 15, 16, 23, 24, 31, 32)

# rate_limit threshold boundary tests. Above u32_max should fail to
# compile per the Finding 1 fix; below 1 should also fail.
_RL_BOUNDARIES = (1, 2, 1023, 1024, 65535, 65536, (1 << 32) - 1)


def _pkt(builder: str) -> str:
  """Build a minimal .pkt body around a builder expression."""
  return (
    f"test_packet:\n  builder: {builder}\n"
    f"\nexpected:\n  compiles: true\n  bpf_action: drop\n"
  )


def _pkt_allow(builder: str) -> str:
  """Build a minimal .pkt body with expected: allow."""
  return (
    f"test_packet:\n  builder: {builder}\n"
    f"\nexpected:\n  compiles: true\n  bpf_action: allow\n"
  )


def _port_boundary_cases() -> Iterable[Candidate]:
  """For each interesting port value: one match, one one-off."""
  for port in _PORT_BOUNDARIES:
    # Match case: rule fires, packet has the same port.
    name = f"port_eq_{port}_match"
    fw = (
      f"@xdp(eth0)\n"
      f"drop if pkt.proto == tcp and pkt.dst_port == {port}\n"
      f"default allow\n"
    )
    body = (
      f"name: \"port {port} matches drop\"\n"
      f"source_fw: |\n  @xdp(eth0)\n"
      f"  drop if pkt.proto == tcp and pkt.dst_port == {port}\n"
      f"  default allow\n\n"
      + _pkt(f"tcp(dst_port={port})")
    )
    yield Candidate(
      name=slug(name),
      fw_source=fw,
      pkt_yaml=body,
      expected_action="drop",
      rationale=f"dst_port == {port} matches packet on the boundary",
      tags=["port-boundary"],
    )

    # Off-by-one neighbor: rule fires for `port`, packet uses port+1.
    if port < 65535:
      neighbor = port + 1
      fw_neighbor = (
        f"@xdp(eth0)\n"
        f"drop if pkt.proto == tcp and pkt.dst_port == {port}\n"
        f"default allow\n"
      )
      body_neighbor = (
        f"name: \"port {port} does not match {neighbor}\"\n"
        f"source_fw: |\n  @xdp(eth0)\n"
        f"  drop if pkt.proto == tcp and pkt.dst_port == {port}\n"
        f"  default allow\n\n"
        + _pkt_allow(f"tcp(dst_port={neighbor})")
      )
      yield Candidate(
        name=slug(f"port_eq_{port}_no_match_at_{neighbor}"),
        fw_source=fw_neighbor,
        pkt_yaml=body_neighbor,
        expected_action="allow",
        rationale=(
          f"dst_port == {port} should not match neighbor {neighbor}"
        ),
        tags=["port-boundary"],
      )


def _port_range_boundary_cases() -> Iterable[Candidate]:
  """Probe range edges: lo, hi, lo-1, hi+1."""
  for lo, hi in ((1024, 65535), (80, 80), (0, 1023)):
    for probe, expect in (
      (lo, "drop"),
      (hi, "drop"),
      (lo - 1 if lo > 0 else None, "allow"),
      (hi + 1 if hi < 65535 else None, "allow"),
    ):
      if probe is None:
        continue
      fw = (
        f"@xdp(eth0)\n"
        f"drop if pkt.proto == tcp and pkt.dst_port in {lo}..{hi}\n"
        f"default allow\n"
      )
      pkt_body = (
        _pkt(f"tcp(dst_port={probe})") if expect == "drop"
        else _pkt_allow(f"tcp(dst_port={probe})")
      )
      body = (
        f"name: \"port range {lo}..{hi} probe {probe} -> {expect}\"\n"
        f"source_fw: |\n  @xdp(eth0)\n"
        f"  drop if pkt.proto == tcp and pkt.dst_port in {lo}..{hi}\n"
        f"  default allow\n\n"
        + pkt_body
      )
      yield Candidate(
        name=slug(f"port_range_{lo}_{hi}_probe_{probe}"),
        fw_source=fw,
        pkt_yaml=body,
        expected_action=expect,
        rationale=(
          f"port range {lo}..{hi} boundary: probe={probe} expect={expect}"
        ),
        tags=["port-range-boundary"],
      )


def _cidr_boundary_cases() -> Iterable[Candidate]:
  """For each CIDR prefix bit count: match at boundary IP.

  Always probes the prefix's base address (10.0.0.0) — that matches
  every prefix length from /0 through /32 by construction. (The
  earlier code probed 10.0.0.1 for bits >= 24, which silently misses
  /32 because /32 is an exact-host match.)
  """
  for bits in _CIDR_BOUNDARIES:
    probe_ip = "1.2.3.4" if bits == 0 else "10.0.0.0"
    fw = (
      f"@xdp(eth0)\n"
      f"drop if pkt.src_ip in 10.0.0.0/{bits}\n"
      f"default allow\n"
    )
    body = (
      f"name: \"cidr /{bits} matches {probe_ip}\"\n"
      f"source_fw: |\n  @xdp(eth0)\n"
      f"  drop if pkt.src_ip in 10.0.0.0/{bits}\n"
      f"  default allow\n\n"
      + _pkt(f"tcp(src_ip=\"{probe_ip}\")")
    )
    yield Candidate(
      name=slug(f"cidr_{bits}_matches_{probe_ip}"),
      fw_source=fw,
      pkt_yaml=body,
      expected_action="drop",
      rationale=f"CIDR /{bits} boundary mask test",
      tags=["cidr-boundary"],
    )


def _rate_limit_boundary_cases() -> Iterable[Candidate]:
  """Sweep rate_limit thresholds — both valid and out-of-range."""
  for threshold in _RL_BOUNDARIES:
    fw = (
      f"@xdp(eth0)\n"
      f"drop if pkt.proto == tcp\n"
      f"     limited by rate_limit({threshold}, per=src_ip)\n"
      f"default allow\n"
    )
    # No state -> bucket is 0, so as long as threshold > 0 the rule
    # fires. (Threshold above u32_max is rejected by the analyzer
    # post-Finding-1.)
    body = (
      f"name: \"rate_limit threshold {threshold}\"\n"
      f"source_fw: |\n  @xdp(eth0)\n"
      f"  drop if pkt.proto == tcp\n"
      f"       limited by rate_limit({threshold}, per=src_ip)\n"
      f"  default allow\n\n"
      + _pkt("tcp(src_ip=\"1.2.3.4\")")
    )
    yield Candidate(
      name=slug(f"rate_limit_threshold_{threshold}"),
      fw_source=fw,
      pkt_yaml=body,
      expected_action="drop",
      rationale=(
        f"rate_limit threshold = {threshold} (boundary or just past)"
      ),
      tags=["rate-limit-boundary"],
    )


def generate(target=None) -> Iterable[Candidate]:
  """Generate every boundary case. `target` is unused (we don't read
  the user's program for this strategy — we generate from scratch)."""
  yield from _port_boundary_cases()
  yield from _port_range_boundary_cases()
  yield from _cidr_boundary_cases()
  yield from _rate_limit_boundary_cases()
