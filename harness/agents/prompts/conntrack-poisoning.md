# Hunt focus: conntrack-poisoning

Find a packet **sequence** that creates a NAT/conntrack mapping that
should not exist, allowing unauthorized traffic — e.g. an attacker frame
that installs a reply mapping in `fwl_nat` letting later inbound traffic
reach an internal host it should not.

Probe the mapping lifecycle in `../f/fwl/fwl/emitter.py`
(`fwl_snat_egress` / `fwl_dnat_ingress` install reply entries;
`fwl_nat_denat` consumes them) and the interpreter's `NatState`:

- **Spoofed reply key:** the egress SNAT reply entry is keyed on
  `(proto, remote, wan_ip, remote_port, preserved_port)`. Can an
  external attacker who guesses/observes the preserved source port
  forge a frame matching that key and get de-NAT'd to the internal
  host? Is the mapping too loosely keyed?
- **Mapping without authorization:** does a `dnat` install its reply
  (SNAT-restore) entry even when the packet is ultimately dropped by a
  later rule? A drop on a `new` packet must not leave state behind
  (mirror the conntrack rule: drop creates nothing).
- **Port-preservation collisions:** two internal hosts behind the same
  `snat`/`masquerade` target with the same source port — does one
  flow's reply mapping mis-route the other's return traffic?
- **Cross-zone leakage:** the `fwl_nat` map is shared (bpffs-pinned)
  across zones. Can a frame on one zone install a mapping that another
  zone's de-NAT pass applies incorrectly?

A finding is an ordered `sequence:` `.pkt` (packet 1 installs/should-not
install state, packet 2 observes the consequence) where the oracles
diverge or the behavior contradicts the rule's intent. Write to
`<kb>/corpus/from_hunt/` and run `fwl test`.
