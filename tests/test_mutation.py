"""Unit tests for the mutation engine's generators.

End-to-end mutate_finding() needs the fwl binary; covered by the
integration smoke. These tests verify the deterministic generators
produce well-formed mutants from a sample (.fw, .pkt) PoC.
"""
from __future__ import annotations

from harness.mutation.engine import (
  _parse_builder_line,
  _port_neighbors,
  _src_ip_neighbors,
  _swap_builder,
  mutate_pkt,
)


_SAMPLE_PKT = """\
name: "ssh first syn"
test_packet:
  builder: tcp(src_ip="9.9.9.9", dst_port=22, syn=true, ack=false)
expected:
  compiles: true
  bpf_action: allow
"""

_SAMPLE_FW = """\
@xdp(eth0)
drop if pkt.proto == tcp
       and pkt.dst_port == 22
       and pkt.tcp.syn and not pkt.tcp.ack
       limited by rate_limit(3, per=src_ip)
default allow
"""


def test_parse_builder_line():
  proto, args = _parse_builder_line(_SAMPLE_PKT)
  assert proto == "tcp"
  assert args["src_ip"] == '"9.9.9.9"'
  assert args["dst_port"] == "22"
  assert args["syn"] == "true"


def test_swap_builder_replaces_only_builder_line():
  out = _swap_builder(_SAMPLE_PKT, "udp", {"dst_port": "53"})
  assert "builder: udp(dst_port=53)" in out
  assert "name: \"ssh first syn\"" in out
  assert "compiles: true" in out


def test_port_neighbors_includes_boundaries():
  ns = _port_neighbors(22)
  assert 0 in ns and 1 in ns and 65535 in ns and 21 in ns and 23 in ns
  assert 22 not in ns


def test_src_ip_neighbors_bumps_last_octet():
  ns = _src_ip_neighbors('"9.9.9.9"')
  assert '"9.9.9.8"' in ns
  assert '"9.9.9.10"' in ns


def test_src_ip_neighbors_clips_at_boundary():
  assert _src_ip_neighbors('"9.9.9.0"') == ['"9.9.9.1"']
  assert _src_ip_neighbors('"9.9.9.255"') == ['"9.9.9.254"']


def test_mutate_pkt_emits_diverse_mutants():
  mutants = mutate_pkt(_SAMPLE_FW, _SAMPLE_PKT, parent_name="parent")
  kinds = {m.mutation for m in mutants}
  # All applicable strategies should fire on this PoC.
  assert {
    "port_shift", "proto_swap", "src_ip_octet",
    "tcp_flag_toggle", "threshold_bump",
  } <= kinds


def test_mutate_pkt_threshold_bump_writes_modified_fw():
  mutants = mutate_pkt(_SAMPLE_FW, _SAMPLE_PKT, parent_name="parent")
  threshold_mutants = [m for m in mutants if m.mutation == "threshold_bump"]
  ns = sorted({
    int(m.fw_source.split("rate_limit(")[1].split(",")[0])
    for m in threshold_mutants
  })
  # 3-1=2, 3+1=4, 3+10=13. Original 3 must NOT appear in mutants.
  assert ns == [2, 4, 13]


def test_mutate_pkt_proto_swap_drops_state():
  mutants = mutate_pkt(
    _SAMPLE_FW,
    _SAMPLE_PKT + "\nstate:\n  rate_limit:\n    0:\n      \"9.9.9.9\": 5\n",
    parent_name="parent",
  )
  swap = [m for m in mutants if m.mutation == "proto_swap"][0]
  assert "state" not in swap.pkt_yaml or "rate_limit:" not in swap.pkt_yaml


def test_mutate_pkt_tags_propagate():
  mutants = mutate_pkt(_SAMPLE_FW, _SAMPLE_PKT, parent_name="p")
  assert all("mutation" in m.tags for m in mutants)
