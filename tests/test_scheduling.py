"""Unit tests for the strategy registry + UCB1 weight recompute."""
from __future__ import annotations
import math
import random
from pathlib import Path

from harness.scheduling import (
  StrategyStats,
  draw_weighted,
  record_run,
  recompute_weights,
)
from harness.scheduling.registry import _FLOOR, load


def test_record_run_creates_state(tmp_path: Path) -> None:
  record_run(tmp_path, "boundary_probing", hits=2, cost_usd=0.0)
  reg = load(tmp_path)
  assert "boundary_probing" in reg.stats
  s = reg.stats["boundary_probing"]
  assert s.hits == 2 and s.runs == 1
  assert reg.weights["boundary_probing"] == _FLOOR
  # Run log was appended.
  log = (tmp_path / "meta" / "strategy_runs.jsonl").read_text()
  assert "boundary_probing" in log


def test_record_run_aggregates(tmp_path: Path) -> None:
  for hits in (3, 1, 2):
    record_run(tmp_path, "boundary_probing", hits=hits)
  s = load(tmp_path).stats["boundary_probing"]
  assert s.runs == 3 and s.hits == 6


def test_recompute_weights_normalises(tmp_path: Path) -> None:
  record_run(tmp_path, "boundary_probing", hits=10, cost_usd=0.0)
  record_run(tmp_path, "oracle_divergence", hits=2, cost_usd=0.0)
  reg = recompute_weights(tmp_path)
  assert math.isclose(sum(reg.weights.values()), 1.0, rel_tol=1e-6)
  # The high-hit strategy should outweigh the low-hit one.
  assert reg.weights["boundary_probing"] > reg.weights["oracle_divergence"]
  assert reg.weights["oracle_divergence"] >= _FLOOR


def test_recompute_weights_unrun_strategy_gets_top_score(tmp_path):
  """An unrun strategy (runs=0) should be preferred next — UCB1 +inf."""
  record_run(tmp_path, "alpha", hits=5, cost_usd=0.0)
  # Inject a stats entry with runs=0 by recording 0-hit runs and then
  # erasing run counts? Easier: record a brand-new strategy by writing
  # weights-side directly via record_run with hits=0 only on first.
  # We simulate "registered but not run" by manual edit:
  reg = load(tmp_path)
  reg.stats["beta"] = StrategyStats(name="beta", runs=0, hits=0)
  reg.weights["beta"] = _FLOOR
  from harness.scheduling.registry import save
  save(tmp_path, reg)
  reg2 = recompute_weights(tmp_path)
  assert reg2.weights["beta"] >= reg2.weights["alpha"]


def test_draw_weighted_respects_weights(tmp_path: Path) -> None:
  record_run(tmp_path, "alpha", hits=100, cost_usd=0.0)
  record_run(tmp_path, "beta", hits=1, cost_usd=0.0)
  recompute_weights(tmp_path)
  rng = random.Random(0)
  draws = [draw_weighted(tmp_path, rng=rng) for _ in range(2000)]
  alpha_share = draws.count("alpha") / len(draws)
  # Loose bound — alpha should win majority but beta isn't starved.
  assert 0.55 <= alpha_share <= 0.95


def test_draw_weighted_empty_returns_none(tmp_path: Path) -> None:
  assert draw_weighted(tmp_path) is None


def test_history_jsonl_appends_per_recompute(tmp_path: Path) -> None:
  record_run(tmp_path, "alpha", hits=1)
  recompute_weights(tmp_path)
  recompute_weights(tmp_path)
  hist = (tmp_path / "meta" / "strategy_history.jsonl").read_text()
  assert len(hist.strip().splitlines()) == 2
