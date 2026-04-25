"""Loop 5 — Strategy registry + auto-tune.

Tracks per-strategy hits (confirmed findings) and cost (USD) over a
rolling window. Recomputes weights using UCB1 so the scheduler
explores under-tested arms while exploiting strategies that have
been productive. The weights determine which strategy `hone schedule`
draws next.

State lives in <kb>/meta/strategy_weights.json and is appended to
<kb>/meta/strategy_history.jsonl after each tune so the evolution
is auditable.

Per HONE_SELF_IMPROVEMENT.md loop 5: epsilon-greedy or UCB1, every
strategy gets a 5% floor so nothing starves permanently, and the
"explore" arm occasionally runs the worst-performing strategy.
"""
from .registry import (
  StrategyRegistry,
  StrategyStats,
  draw_weighted,
  record_run,
  recompute_weights,
)

__all__ = [
  "StrategyRegistry",
  "StrategyStats",
  "draw_weighted",
  "record_run",
  "recompute_weights",
]
