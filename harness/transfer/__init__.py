"""Loop 4 — Cross-program transfer.

A bug found in program A may exist in program B if B uses the same
construct combination. When a finding lands, extract its construct
signature, scan a target set for overlapping signatures, and run
the parent's PoC packet (with the parent's expected outcome) against
each candidate program.

Cheap and deterministic — no LLM cost. Per
HONE_SELF_IMPROVEMENT.md loop 4: "fix once, check everywhere".
"""
from .engine import (
  ConstructSignature,
  TransferResult,
  signature_of_finding,
  signature_of_program,
  transfer_finding,
)

__all__ = [
  "ConstructSignature",
  "TransferResult",
  "signature_of_finding",
  "signature_of_program",
  "transfer_finding",
]
