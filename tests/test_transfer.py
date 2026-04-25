"""Unit tests for the transfer engine's signature + scoring."""
from __future__ import annotations

from harness.transfer.engine import (
  ConstructSignature,
  signature_of_program,
)


_SSH = """\
@xdp(eth0)
drop if pkt.proto == tcp
       and pkt.dst_port == 22
       and pkt.tcp.syn and not pkt.tcp.ack
       limited by rate_limit(3, per=src_ip)
default allow
"""

_DDOS = """\
@xdp(eth0)
drop limited by rate_limit(1000, per=src_ip)
allow if pkt.proto == tcp and pkt.dst_port in [80, 443]
default drop
"""

_INTERNAL = """\
@xdp(eth0)
allow if pkt.src_ip in [10.0.0.0/8, 172.16.0.0/12]
allow if pkt.proto == udp and pkt.dst_port == 53
default drop
"""


def test_signature_extracts_protocols_and_builtins():
  sig = signature_of_program(_SSH)
  assert "tcp" in sig.protocols
  assert "rate_limit" in sig.builtins
  assert sig.has_rate_limit is True
  assert sig.has_default is True


def test_signature_no_rate_limit():
  sig = signature_of_program(_INTERNAL)
  assert sig.has_rate_limit is False
  assert "rate_limit" not in sig.builtins


def test_jaccard_self_equal():
  sig = signature_of_program(_SSH)
  # Self-similarity should be at the bonus ceiling (>= 1.0 capped).
  assert sig.jaccard(sig) >= 0.95


def test_jaccard_ssh_vs_ddos_high():
  # Both use rate_limit + tcp. Should be a strong match.
  sig_a = signature_of_program(_SSH)
  sig_b = signature_of_program(_DDOS)
  assert sig_a.jaccard(sig_b) >= 0.4


def test_jaccard_ssh_vs_internal_low():
  # Internal uses no rate_limit and no TCP-specific fields.
  sig_a = signature_of_program(_SSH)
  sig_b = signature_of_program(_INTERNAL)
  assert sig_a.jaccard(sig_b) < sig_a.jaccard(signature_of_program(_DDOS))


def test_jaccard_empty_signatures():
  assert ConstructSignature().jaccard(ConstructSignature()) == 0.0
