# Hunt focus: nat-bypass

Find a packet (or short sequence) that **bypasses NAT and leaks the
internal address** to the external network — i.e. a frame that *should*
be source-rewritten by a `snat`/`masquerade` program but leaves with its
original internal source IP, or a frame that should be de-NAT'd on
return but isn't.

Concrete angles to probe in `../f/fwl/fwl/emitter.py` (`_NAT_HELPERS`,
`fwl_find_ipv4`, `fwl_snat_egress`, `fwl_nat_denat`) and the interpreter
model (`interpreter.py` `NatState`, `_apply_nat`, `_apply_ingress_denat`):

- **Guard gaps:** a NAT action guarded on `pkt.proto == tcp` — does a
  non-TCP, fragmented, or truncated frame slip through unrewritten while
  the rule's intent was to NAT the flow?
- **IHL / options:** `fwl_find_ipv4` only rewrites `ihl == 5`. Craft a
  frame with IP options (ihl > 5) — does it leak the internal src
  un-NAT'd? Is that a documented limitation or a real leak?
- **VLAN offset:** a single 802.1Q tag shifts the IP header. Does the
  NAT path find the IP header on a tagged frame, or skip the rewrite?
- **Action ordering:** is there a rule order where a terminal action
  (allow/redirect) fires *before* the intended `snat`, so the packet
  egresses unrewritten?
- **Oracle divergence:** does the interpreter's `output_packet` claim a
  rewrite the BPF program does not actually perform (or vice versa)?

A finding is a `.pkt` where `expected.output_packet` (or the absence of
one) demonstrates the leak, with interpreter and BPF disagreeing OR both
agreeing on a behavior the rule's intent contradicts. Write it to
`<kb>/corpus/from_hunt/` and run `fwl test`.
