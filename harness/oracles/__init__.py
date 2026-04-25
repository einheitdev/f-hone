"""Oracle wrappers around the FWL compiler.

Three oracles per F_SECURITY_HARNESS.md:
  1. AST interpreter (calls `fwl interpret`)
  2. BPF runtime (calls `fwl test` / BPF_PROG_TEST_RUN)
  3. Protocol spec checker (RFC-based, deferred)

Each wrapper takes a (.fw program, .pkt test packet) pair and returns a
structured outcome. Disagreement between oracles is the strongest bug
signal.
"""
