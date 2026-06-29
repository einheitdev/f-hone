"""cross_family_nat — run the same NAT program against paired IPv4 and
IPv6 frames (Phase 5).

v0.4 NAT is IPv4-only: an IPv4 frame is translated (source/destination
rewritten, checksums fixed), while an IPv6 frame on the identical
program must pass through untouched (no rewrite, no map entry). Each
pair asserts the v4 result (with output_packet, so checksums are
validated) and that the v6 frame's action matches with no rewrite — the
oracles must agree on both families. A NAT path that mishandled the
family gate (e.g. rewrote a v6 frame, or skipped a v4 one) shows up as a
bpf/interpreter divergence or a checksum failure.
"""
from __future__ import annotations
from typing import Iterable

from .common import Candidate, slug

_V4 = [("10.0.0.5", "198.51.100.9", "93.184.216.34"),
       ("192.168.1.50", "203.0.113.1", "1.1.1.1"),
       ("172.16.0.9", "198.51.100.2", "8.8.8.8"),
       ("10.1.2.3", "203.0.113.250", "140.82.112.3"),
       ("10.9.9.9", "198.51.100.77", "151.101.0.1")]
_V6 = ["2001:db8::5", "2001:db8:1::9", "fd00::1", "2001:db8:abcd::1234"]
_PORTS = [80, 443, 12345, 40000, 53, 8080]


def _body(name, fw, builder, action, output=None) -> str:
  out = ""
  if output:
    op = "\n".join(f"    {k}: {v}" for k, v in output.items())
    out = f"  output_packet:\n{op}\n"
  return (
    f'name: "{name}"\n'
    f"source_fw: |\n" + "".join(f"  {ln}\n" for ln in fw.splitlines())
    + f"test_packet:\n  builder: {builder}\n"
    f"expected:\n  compiles: true\n  bpf_action: {action}\n" + out
  )


def generate(target=None) -> Iterable[Candidate]:
  i = 0
  for inside, nip, remote in _V4:
    sport = _PORTS[i % len(_PORTS)]
    dport = _PORTS[(i + 1) % len(_PORTS)]
    # The same SNAT program; the @xdp interface name (eth0) keeps both
    # families on one degenerate zone.
    fw = (f"@xdp(eth0)\nsnat to {nip} if pkt.proto == tcp\nallow\n")
    # IPv4: translated.
    yield Candidate(
      name=slug(f"xfam v4 snat {inside}->{nip}"),
      fw_source=fw,
      pkt_yaml=_body(
        f"cross-family v4 SNAT {inside} -> {nip}", fw,
        f'tcp(src_ip="{inside}", dst_ip="{remote}", '
        f'src_port={sport}, dst_port={dport}, syn=true)',
        "allow",
        {"src_ip": f'"{nip}"', "dst_ip": f'"{remote}"',
         "src_port": sport}),
      expected_action="allow", rationale="v4 SNAT translates",
      tags=["nat", "cross-family", "ipv4"],
    )
    # IPv6: same program, v6 frame — NAT is IPv4-only, so no rewrite.
    v6src = _V6[i % len(_V6)]
    v6dst = _V6[(i + 2) % len(_V6)]
    yield Candidate(
      name=slug(f"xfam v6 noop {v6src}"),
      fw_source=fw,
      pkt_yaml=_body(
        f"cross-family v6 frame is not NAT'd (IPv4-only)", fw,
        f'tcp6(src_ip="{v6src}", dst_ip="{v6dst}", '
        f'src_port={sport}, dst_port={dport}, syn=true)',
        "allow"),
      expected_action="allow", rationale="v6 frame untouched by NAT",
      tags=["nat", "cross-family", "ipv6"],
    )
    i += 1
