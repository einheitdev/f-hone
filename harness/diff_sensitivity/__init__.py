"""Loop 7 — Compiler diff sensitivity.

When a new commit lands in the FWL compiler, parse the diff, map
changed files/symbols to FWL constructs (per a static yaml map),
and surface the impacted construct set as a strategy-weight boost
recommendation. The scheduler can then bias the next round toward
strategies that exercise those constructs.

No LLM cost. Per HONE_SELF_IMPROVEMENT.md loop 7: change-aware
testing — focus on what just changed instead of re-testing
everything uniformly.
"""
from .engine import (
  ConstructImpact,
  diff_impact,
  load_construct_map,
)

__all__ = [
  "ConstructImpact",
  "diff_impact",
  "load_construct_map",
]
