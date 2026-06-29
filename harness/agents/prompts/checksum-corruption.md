# Hunt focus: checksum-corruption

Find a NAT rewrite that produces an **invalid IP or L4 checksum**,
causing the rewritten frame to be silently dropped downstream. These
bugs compile cleanly, pass the interpreter (which models fields, not
checksums), and only surface on a real kernel — so lean on the BPF
oracle, which (Phase 5) recomputes IP + TCP/UDP checksums of every
asserted `output_packet` and fails on a mismatch.

Probe the checksum math in `../f/fwl/fwl/emitter.py`:
`fwl_csum_fold`, `fwl_fix_ip_csum` (uses `bpf_csum_diff`), and
`fwl_l4_fix` (manual native-endian RFC 1624 incremental update):

- **Carry / fold edge cases:** craft addresses and ports whose
  one's-complement sum carries through 16-bit boundaries repeatedly
  (e.g. `255.255.x.y`, ports near 65535) — does the double-fold hold?
- **UDP zero checksum:** a UDP datagram with checksum 0 means "no
  checksum". Does the rewrite correctly leave it 0, or does it compute
  a (wrong) non-zero value? And the 0 → 0xffff rule when a computed
  checksum folds to 0?
- **Combined addr+port (DNAT):** the destination rewrite changes both
  the address (IP + pseudo-header) and the port — is the L4 delta the
  sum of both, or does one get dropped?
- **De-NAT path:** `fwl_nat_denat` rewrites the *other* side on return
  traffic — does its checksum update mirror the egress one correctly?
- **Byte order:** the L4 field is read as a host u16; the address as
  network-order bytes. A byte-order slip yields a wrong-but-plausible
  checksum (the original 5.1 bug). Hunt for a case the BPF oracle's
  recompute rejects.

To verify on a real kernel, drive the case through `BPF_PROG_TEST_RUN`
and validate with scapy (see the Phase 5 proof scripts). A finding is a
`.pkt` whose rewritten frame the BPF oracle reports as
`*checksum invalid after rewrite*`. Write to `<kb>/corpus/from_hunt/`.
