"""checksum_verify — generate NAT rewrites and assert the result has
valid IP + L4 checksums (Phase 5).

Every candidate is a SNAT/DNAT program plus a packet whose `.pkt` states
the post-rewrite 5-tuple via `expected.output_packet`. The BPF oracle
verifies those fields AND (because output_packet is asserted) recomputes
the IP and TCP/UDP checksums of the rewritten frame, failing on any
invalid checksum. Running this strategy over its full sweep exercises
"zero invalid checksums across N NAT rewrites": a checksum bug surfaces
as a `bpf fail` on the offending case.
"""
from __future__ import annotations
from typing import Iterable

from .common import Candidate, slug

# A spread of inside hosts, NAT targets, remote peers, and ports so the
# 16-bit one's-complement arithmetic is exercised across many carry
# patterns (the regime where fold/sign bugs hide).
_INSIDE = ["10.0.0.5", "192.168.1.50", "172.16.0.9", "10.1.2.3",
           "10.255.0.1", "192.168.250.250", "172.31.255.9", "10.0.0.255",
           "192.168.0.1", "172.20.30.40"]
_NAT_IP = ["198.51.100.9", "203.0.113.1", "198.51.100.255", "203.0.113.250",
           "1.2.3.4", "255.1.255.1", "200.100.50.25", "198.51.100.128",
           "203.0.113.99", "11.22.33.44"]
_REMOTE = ["93.184.216.34", "8.8.8.8", "1.1.1.1", "140.82.112.3",
           "151.101.0.1", "208.67.222.222", "9.9.9.9", "104.16.0.1",
           "13.107.21.200", "185.199.108.1"]
_PORTS = [1, 80, 443, 1024, 12345, 40000, 53, 65535, 8080, 5353]


def _case(name, fw, builder, output, action="allow") -> Candidate:
  op = "\n".join(f"    {k}: {v}" for k, v in output.items())
  body = (
    f'name: "{name}"\n'
    f"source_fw: |\n" + "".join(f"  {ln}\n" for ln in fw.splitlines())
    + f"test_packet:\n  builder: {builder}\n"
    f"expected:\n  compiles: true\n  bpf_action: {action}\n"
    f"  output_packet:\n{op}\n"
  )
  return Candidate(
    name=slug(name), fw_source=fw, pkt_yaml=body,
    expected_action=action, rationale=name, tags=["nat", "checksum"],
  )


def generate(target=None) -> Iterable[Candidate]:
  i = 0
  # SNAT TCP + UDP: source rewritten, port-preserving — IP + L4 checksums
  # must stay valid.
  for proto in ("tcp", "udp"):
    for inside in _INSIDE:
      for nip in _NAT_IP:
        remote = _REMOTE[i % len(_REMOTE)]
        sport = _PORTS[i % len(_PORTS)]
        dport = _PORTS[(i + 3) % len(_PORTS)]
        i += 1
        syn = ", syn=true" if proto == "tcp" else ""
        b = (f'{proto}(src_ip="{inside}", dst_ip="{remote}", '
             f'src_port={sport}, dst_port={dport}{syn})')
        yield _case(
          f"snat {i} {proto} {inside}->{nip} {sport} {dport} csum",
          f"@xdp(lan)\nsnat to {nip} if pkt.proto == {proto}\nallow\n",
          b,
          {"src_ip": f'"{nip}"', "dst_ip": f'"{remote}"',
           "src_port": sport},
        )
  # DNAT TCP: destination addr+port rewritten — both checksums must hold
  # across the combined address+port delta.
  for remote in _REMOTE:
    for nip in _INSIDE:
      for ndport in _PORTS:
        sport = _PORTS[i % len(_PORTS)]
        i += 1
        ext = _NAT_IP[i % len(_NAT_IP)]
        b = (f'tcp(src_ip="{remote}", dst_ip="{ext}", '
             f'src_port={sport}, dst_port=80, syn=true)')
        yield _case(
          f"dnat {i} tcp {ext}:80->{nip}:{ndport} sp{sport} csum",
          f"@xdp(wan)\ndnat to {nip}:{ndport} if pkt.proto == tcp "
          f"and pkt.dst_port == 80\nallow\n",
          b,
          {"src_ip": f'"{remote}"', "dst_ip": f'"{nip}"',
           "dst_port": ndport},
        )
