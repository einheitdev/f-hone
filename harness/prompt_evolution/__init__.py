"""Loop 1 — Prompt evolution (DEFERRED, infrastructure pending).

Per HONE_SELF_IMPROVEMENT.md loop 1: a meta-agent reads the last N
hypotheses with their hit/miss outcomes and rewrites the hypothesis
system prompt to emphasize framings that correlate with confirmed
findings. Versioned in <kb>/meta/prompts/.

This is a stub. The infrastructure prerequisites are:

  1. Per-hypothesis outcome capture. Today the hone hunt agent
     writes findings/misses but doesn't tag each one with the exact
     hypothesis prompt that produced it. Add a `hypothesis:` field
     to finding/miss frontmatter so we can correlate.

  2. Prompt versioning + diff. Need a place to stash prompt text
     blobs (`<kb>/meta/prompts/<version>.md`) and a tiny rollback
     mechanism so a regression can be reverted by switching back to
     the previous version.

  3. A meta-agent that reads N>=200 (hypothesis, outcome) pairs and
     proposes a prompt rewrite. This is a separate Claude session;
     plumb on top of the existing claude_code_sdk wrapper.

The doc estimates 200+ hypotheses (2-3 months of operation) before
the data is statistically distinguishable. Tracking this work as
v0.2 — see docs/HONE_SELF_IMPROVEMENT.md.
"""


class NotYetImplementedError(NotImplementedError):
  """Marker so callers see a deliberate deferral, not a missing feature."""
  pass


def evolve_prompt(*args, **kwargs):
  """Placeholder for the prompt-evolution meta-agent."""
  raise NotYetImplementedError(
    "Loop 1 (prompt evolution) is deferred to hone v0.2. "
    "See harness/prompt_evolution/__init__.py for the prerequisites "
    "and docs/HONE_SELF_IMPROVEMENT.md for the design."
  )
