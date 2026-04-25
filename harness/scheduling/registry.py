"""Strategy registry, hit/cost tracking, UCB1 weight recompute.

State files (under <kb>/meta/):

  strategy_weights.json   current weights, last tuned timestamp
  strategy_history.jsonl  one line per recompute (hits/cost/weight)
  strategy_runs.jsonl     one line per `record_run` call (raw events)

The registry is intentionally append-only at the JSONL layer so
recompute is replayable; the JSON file is just a cache of the most
recent UCB1 result.
"""
from __future__ import annotations
import json
import math
import random
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


_FLOOR = 0.05  # minimum weight per strategy — prevents starvation
_DEFAULT_C = math.sqrt(2)  # UCB1 exploration constant


@dataclass
class StrategyStats:
  """Per-strategy aggregate over the recorded runs."""
  name: str
  hits: int = 0
  runs: int = 0
  cost_usd: float = 0.0

  @property
  def hits_per_run(self) -> float:
    return self.hits / self.runs if self.runs else 0.0

  @property
  def hits_per_dollar(self) -> float:
    """Inf when cost is zero (deterministic strategies); used to
    prioritise free wins over expensive maybes in the tuner."""
    return self.hits / self.cost_usd if self.cost_usd > 0 else math.inf


@dataclass
class StrategyRegistry:
  """Snapshot of the registry at one point in time."""
  weights: dict[str, float] = field(default_factory=dict)
  stats: dict[str, StrategyStats] = field(default_factory=dict)
  last_tuned: str | None = None

  def to_dict(self) -> dict:
    return {
      "weights": self.weights,
      "stats": {k: asdict(v) for k, v in self.stats.items()},
      "last_tuned": self.last_tuned,
    }

  @classmethod
  def from_dict(cls, data: dict) -> "StrategyRegistry":
    return cls(
      weights=dict(data.get("weights", {})),
      stats={
        k: StrategyStats(**v) for k, v in data.get("stats", {}).items()
      },
      last_tuned=data.get("last_tuned"),
    )


def _meta_dir(kb_root: Path) -> Path:
  d = kb_root / "meta"
  d.mkdir(parents=True, exist_ok=True)
  return d


def _weights_path(kb_root: Path) -> Path:
  return _meta_dir(kb_root) / "strategy_weights.json"


def _runs_path(kb_root: Path) -> Path:
  return _meta_dir(kb_root) / "strategy_runs.jsonl"


def _history_path(kb_root: Path) -> Path:
  return _meta_dir(kb_root) / "strategy_history.jsonl"


def _now_iso() -> str:
  return datetime.now(timezone.utc).isoformat()


def load(kb_root: Path) -> StrategyRegistry:
  """Read the current registry; empty if no state has been written yet."""
  path = _weights_path(kb_root)
  if not path.exists():
    return StrategyRegistry()
  return StrategyRegistry.from_dict(
    json.loads(path.read_text(encoding="utf-8"))
  )


def save(kb_root: Path, reg: StrategyRegistry) -> None:
  """Persist the current registry snapshot atomically."""
  path = _weights_path(kb_root)
  tmp = path.with_suffix(".json.tmp")
  tmp.write_text(json.dumps(reg.to_dict(), indent=2), encoding="utf-8")
  tmp.replace(path)


def record_run(
  kb_root: Path,
  strategy: str,
  hits: int,
  cost_usd: float = 0.0,
) -> None:
  """Append one run event to strategy_runs.jsonl AND fold it into
  the in-memory stats. Cheap; safe to call after every strategy
  invocation."""
  event = {
    "ts": _now_iso(),
    "strategy": strategy,
    "hits": int(hits),
    "cost_usd": float(cost_usd),
  }
  with _runs_path(kb_root).open("a", encoding="utf-8") as f:
    f.write(json.dumps(event) + "\n")
  reg = load(kb_root)
  s = reg.stats.setdefault(strategy, StrategyStats(name=strategy))
  s.hits += int(hits)
  s.runs += 1
  s.cost_usd += float(cost_usd)
  if strategy not in reg.weights:
    # First run of a brand-new strategy gets the floor weight; the
    # next recompute will lift it based on actual performance.
    reg.weights[strategy] = _FLOOR
  save(kb_root, reg)


def _ucb1(stats: StrategyStats, total_runs: int, c: float) -> float:
  """UCB1 score for a single arm. Treats unrun arms as +inf so they
  get drawn first (the registry then learns whether they pay)."""
  if stats.runs == 0:
    return math.inf
  exploit = stats.hits / stats.runs
  explore = c * math.sqrt(math.log(max(total_runs, 1)) / stats.runs)
  return exploit + explore


def recompute_weights(
  kb_root: Path,
  c: float = _DEFAULT_C,
) -> StrategyRegistry:
  """Re-derive weights from the accumulated stats using UCB1.

  Weights are normalized to sum to 1.0 with a per-strategy floor of
  5% so a sub-par strategy keeps a small exploration budget.
  Records the recompute event in strategy_history.jsonl so the
  evolution is auditable.
  """
  reg = load(kb_root)
  if not reg.stats:
    return reg
  total_runs = sum(s.runs for s in reg.stats.values())
  raw = {n: _ucb1(s, total_runs, c) for n, s in reg.stats.items()}
  finite = {n: v for n, v in raw.items() if math.isfinite(v)}
  if finite:
    finite_max = max(finite.values()) if finite else 1.0
  else:
    finite_max = 1.0
  # Replace +inf (unrun arms) with the largest finite UCB so they
  # don't dominate weight allocation entirely.
  raw = {
    n: (v if math.isfinite(v) else finite_max + 1.0)
    for n, v in raw.items()
  }
  total = sum(raw.values()) or 1.0
  weights: dict[str, float] = {}
  n_strategies = len(raw)
  reservable = max(0.0, 1.0 - _FLOOR * n_strategies)
  for name, score in raw.items():
    weights[name] = _FLOOR + reservable * (score / total)
  reg.weights = weights
  reg.last_tuned = _now_iso()
  save(kb_root, reg)
  with _history_path(kb_root).open("a", encoding="utf-8") as f:
    f.write(json.dumps({
      "ts": reg.last_tuned,
      "c": c,
      "weights": weights,
      "stats": {n: asdict(s) for n, s in reg.stats.items()},
    }) + "\n")
  return reg


def draw_weighted(
  kb_root: Path,
  strategies: Iterable[str] | None = None,
  rng: random.Random | None = None,
) -> str | None:
  """Draw one strategy name proportional to current weights.

  If `strategies` is given, restrict the draw to that subset (and
  fall back to a uniform distribution if none of them have weights
  yet). Returns None if the registry is empty AND no fallback set
  is given.
  """
  reg = load(kb_root)
  rng = rng or random.Random()
  pool = list(strategies) if strategies else list(reg.weights.keys())
  if not pool:
    return None
  weights = [reg.weights.get(name, _FLOOR) for name in pool]
  if sum(weights) == 0:
    weights = [1.0] * len(pool)
  return rng.choices(pool, weights=weights, k=1)[0]
