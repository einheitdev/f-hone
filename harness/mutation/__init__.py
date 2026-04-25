"""Loop 3 — Finding mutation engine.

When a confirmed finding lands, mutate its PoC packet (port shifts,
proto swaps, src_ip bumps, TCP flag toggles, threshold tweaks on the
program side) and run each mutant through both oracles. Mutants
where the oracles disagree become related findings; mutants where
the oracles still agree map the boundary of the original bug.

No LLM cost — pure deterministic packet mangling. Per
HONE_SELF_IMPROVEMENT.md loop 3, this is the single highest-leverage
loop because every confirmed finding pays compound interest from the
moment it is recorded.
"""
from .engine import mutate_finding, mutate_pkt
from .types import Mutant, MutationOutcome, MutationResult

__all__ = [
  "Mutant",
  "MutationOutcome",
  "MutationResult",
  "mutate_finding",
  "mutate_pkt",
]
