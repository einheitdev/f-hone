"""`hone` command-line interface.

Subcommands per docs/HONE_REPO_DESIGN.md:

  hone regress   Run a .pkt corpus against fwl, report verdict (working)
  hone fuzz      Deterministic discovery strategies (deferred)
  hone hunt      LLM agent pods + Solr context (deferred)
  hone index     (Re)index the knowledge base into Solr (deferred)
  hone report    Summary of findings/coverage/cost (deferred)
  hone abstract  Pattern abstraction pass (deferred)
  hone critique  Self-critique pass on a completed round (deferred)

The deferred subcommands are exposed but exit with a clear "not yet
implemented" message and a pointer to the design doc, so the CLI
surface is stable while implementation lands.
"""
from __future__ import annotations
import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console

from . import __version__
from .oracles.bpf_runner import run_corpus
from .oracles.fwl_subprocess import FwlNotFound, resolve_fwl_bin
from .reporting.console import format_corpus_results
from .strategies import boundary_probing, oracle_divergence
from .strategies.runner import run_strategy

_STRATEGIES = {
  "boundary_probing": boundary_probing.generate,
  "oracle_divergence": oracle_divergence.generate,
}


_console = Console()


def _not_yet(name: str) -> None:
  """Stub for deferred subcommands — exit 2 with a pointer."""
  _console.print(
    f"[yellow]hone {name}[/yellow] is not yet implemented. "
    f"See docs/HONE_REPO_DESIGN.md for the design and the Status "
    f"table in README.md for what's wired up today."
  )
  sys.exit(2)


@click.group()
@click.version_option(__version__, prog_name="hone")
def main() -> None:
  """hone — adversarial security harness for FWL programs."""


@main.command()
@click.option(
  "--corpus", type=click.Path(exists=True, path_type=Path),
  required=True,
  help="Directory of .pkt cases to run (recursive).",
)
@click.option(
  "--fwl-bin", default=None,
  help=(
    "Path to the fwl binary. Defaults to $HONE_FWL_BIN or `fwl` "
    "on PATH."
  ),
)
@click.option(
  "--timeout", type=float, default=600.0,
  help="Wall-clock seconds before killing the run (default: 600).",
)
def regress(corpus: Path, fwl_bin: str | None, timeout: float) -> None:
  """Run the regression corpus against fwl. CI / pre-merge target.

  Shells out to `fwl test <corpus>` and prints a per-case verdict.
  Exits non-zero if any case fails — same contract as `fwl test`,
  with hone-style formatting on top.
  """
  try:
    bin_path = resolve_fwl_bin(fwl_bin)
  except FwlNotFound as exc:
    _console.print(f"[red]{exc}[/red]")
    sys.exit(1)
  verdict = run_corpus(bin_path, corpus, timeout=timeout)
  format_corpus_results(verdict, _console)
  if not verdict.all_passed:
    sys.exit(1)


@main.command()
@click.option(
  "--strategy", "-s",
  type=click.Choice(list(_STRATEGIES.keys()) + ["all"]),
  default="boundary_probing",
  help="Which strategy to run.",
)
@click.option(
  "--kb", type=click.Path(path_type=Path), required=True,
  help="Knowledge base root — findings + corpus get written here.",
)
@click.option(
  "--fwl-bin", default=None,
  help="Path to the fwl binary (defaults to PATH).",
)
@click.option(
  "--count", type=int, default=200,
  help="Number of cases to generate (oracle_divergence only).",
)
@click.option(
  "--seed", type=int, default=0,
  help="RNG seed for stochastic strategies (oracle_divergence).",
)
def fuzz(
  strategy: str, kb: Path, fwl_bin: str | None,
  count: int, seed: int,
) -> None:
  """Deterministic discovery — no LLM, no API cost.

  Generates candidate (program, packet) pairs, runs them through both
  oracles, and writes findings + corpus entries to the knowledge base
  whenever the oracles disagree.
  """
  try:
    bin_path = resolve_fwl_bin(fwl_bin)
  except FwlNotFound as exc:
    _console.print(f"[red]{exc}[/red]")
    sys.exit(1)
  if not kb.exists():
    _console.print(f"[red]knowledge base not found: {kb}[/red]")
    sys.exit(1)

  strategies = (
    list(_STRATEGIES.items()) if strategy == "all"
    else [(strategy, _STRATEGIES[strategy])]
  )

  total_findings = 0
  for name, gen in strategies:
    _console.print(f"\n[bold]running strategy[/bold] [cyan]{name}[/cyan]")
    if name == "oracle_divergence":
      cands = list(gen(count=count, seed=seed))
    else:
      cands = list(gen())
    _console.print(f"  generated {len(cands)} candidates")

    probes, results = run_strategy(
      cands,
      fwl_bin=bin_path,
      kb_root=kb,
      strategy_name=name,
    )

    _console.print(
      f"  agreed:           [green]{results.agree}[/green]\n"
      f"  divergent:        [red bold]{results.divergent}[/red bold]\n"
      f"  compile_failed:   {results.compile_failed}\n"
      f"  runner_error:     {results.runner_error}"
    )
    total_findings += len(results.findings_written)
    for path in results.findings_written:
      _console.print(f"  [red]> finding[/red] {path}")

  _console.print(
    f"\n[bold]total findings written:[/bold] "
    f"[red bold]{total_findings}[/red bold]"
  )
  if total_findings:
    sys.exit(1)


@main.command()
@click.option(
  "--kb", type=click.Path(path_type=Path), required=True,
  help="Knowledge base root — findings + corpus get written here.",
)
@click.option(
  "--target", type=click.Path(exists=True, path_type=Path), default=None,
  help="A .fw file (or directory) to focus the hunt on.",
)
@click.option(
  "--fwl-repo", type=click.Path(exists=True, path_type=Path),
  default=None,
  help="Root of the FWL repo (defaults to <kb>/../f).",
)
@click.option(
  "--max-turns", type=int, default=80,
  help="Turn budget for the agent's loop (default: 80).",
)
@click.option(
  "--model", default="claude-opus-4-7",
  help="Claude model to use for the agent.",
)
@click.option(
  "--solr-url", default="http://localhost:8983/solr/hone",
  help=(
    "Solr URL for retrieval-augmented hunting. Pass empty string "
    "to disable retrieval."
  ),
)
def hunt(
  kb: Path, target: Path | None, fwl_repo: Path | None,
  max_turns: int, model: str, solr_url: str,
) -> None:
  """Agentic bug hunt — Claude reads source, hypothesizes, tests, iterates.

  Spawns a multi-turn Claude session with Read/Bash/Write tools
  enabled, pointing at the knowledge base and the FWL source. The
  agent writes any findings/misses/corpus entries directly to the kb
  in markdown form. Auth is your Claude Code subscription — no API
  key, no separate billing.
  """
  if not kb.exists():
    _console.print(f"[red]knowledge base not found: {kb}[/red]")
    sys.exit(1)

  # Lazy import — claude-code-sdk requires the `claude` CLI to be on
  # PATH and we don't want to error at module load if it isn't.
  from .agents.pod import hunt as _hunt

  _console.print(
    f"[bold]hone hunt[/bold]  kb={kb}  target={target or '(any)'}  "
    f"max_turns={max_turns}"
  )
  result = asyncio.run(_hunt(
    kb_root=kb,
    target=target,
    fwl_repo_root=fwl_repo,
    max_turns=max_turns,
    model=model,
    solr_url=solr_url or None,
  ))
  _console.print(
    f"\n[bold]hunt complete[/bold]  turns={result.turns}  "
    f"cost=${result.total_cost_usd:.4f}  "
    f"prior_context={result.context_items}"
  )


@main.command()
@click.option(
  "--kb", type=click.Path(exists=True, path_type=Path), required=True,
  help="Knowledge base root to index.",
)
@click.option(
  "--solr-url", default="http://localhost:8983/solr/hone",
  help="Solr core URL (default: localhost docker compose).",
)
@click.option(
  "--full", is_flag=True,
  help="Wipe the core before re-indexing (otherwise upsert).",
)
def index(kb: Path, solr_url: str, full: bool) -> None:
  """(Re)index the knowledge base into Solr.

  Walks <kb>/{findings,misses,patterns}/*.md, parses each via the
  knowledge.reader module, and upserts a Solr document per file.
  Idempotent — re-running with no changes is a no-op.
  """
  from .retrieval.indexer import reindex
  from .retrieval.solr_client import SolrClient, SolrError

  client = SolrClient(base_url=solr_url)
  if not client.ping():
    _console.print(
      f"[red]Solr not reachable at {solr_url}.[/red] "
      f"Is the docker compose stack up? "
      f"`docker compose -f docker/docker-compose.yml up -d`"
    )
    sys.exit(1)
  try:
    counts = reindex(kb, client, full=full)
  except SolrError as exc:
    _console.print(f"[red]indexing failed: {exc}[/red]")
    sys.exit(1)
  _console.print(
    f"indexed: findings={counts['findings']}  "
    f"misses={counts['misses']}  patterns={counts['patterns']}  "
    f"total={counts['total']}"
  )


@main.command()
@click.option(
  "--kb", type=click.Path(exists=True, path_type=Path), required=True,
  help="Knowledge base root to summarize.",
)
@click.option(
  "--since", default=None,
  help=(
    "Only count entities created on/after this ISO date "
    "(yyyy-mm-dd). Default: all time."
  ),
)
@click.option(
  "--format", "fmt",
  type=click.Choice(["console", "json"]), default="console",
  help="Output format.",
)
def report(kb: Path, since: str | None, fmt: str) -> None:
  """Summarize findings/misses/patterns by status, severity, layer."""
  from .reporting.stats import build_report, render_console, render_json
  from datetime import date

  cutoff = date.fromisoformat(since) if since else None
  stats = build_report(kb, cutoff=cutoff)
  if fmt == "json":
    print(render_json(stats))
  else:
    render_console(stats, _console)


@main.command()
@click.option(
  "--kb", type=click.Path(exists=True, path_type=Path), required=True,
  help="Knowledge base root.",
)
@click.option(
  "--min-findings", type=int, default=5,
  help="Skip the pass when fewer than N findings exist (default: 5).",
)
@click.option(
  "--max-turns", type=int, default=30,
  help="Turn budget for the agent (default: 30).",
)
@click.option(
  "--model", default="claude-opus-4-7",
  help="Claude model to use.",
)
def abstract(
  kb: Path, min_findings: int, max_turns: int, model: str,
) -> None:
  """Cluster findings into patterns. Drafts go to <kb>/patterns/.

  Reads every finding under <kb>/findings/, asks Claude to group
  them by root-cause shape, and writes one pattern document per
  cluster of 2+ findings. Per F_SECURITY_HARNESS.md the pattern
  abstraction is what turns "a fuzzer that found 50 bugs" into
  "a security methodology that understands 10 classes of bugs."
  """
  from .agents.abstractor import abstract_patterns
  result = asyncio.run(abstract_patterns(
    kb_root=kb, model=model, max_turns=max_turns,
    min_findings=min_findings,
  ))
  _console.print(
    f"\n[bold]abstract complete[/bold]  turns={result.turns}  "
    f"cost=${result.total_cost_usd:.4f}  "
    f"patterns_written={len(result.patterns_written)}"
  )
  for p in result.patterns_written:
    _console.print(f"  [green]> pattern[/green] {p}")


@main.command()
@click.option(
  "--kb", type=click.Path(exists=True, path_type=Path), required=True,
  help="Knowledge base root.",
)
@click.option(
  "--max-turns", type=int, default=30,
  help="Turn budget for the agent (default: 30).",
)
@click.option(
  "--model", default="claude-opus-4-7",
  help="Claude model to use.",
)
def critique(kb: Path, max_turns: int, model: str) -> None:
  """Self-critique pass — what's working, what to tune.

  Reads recent findings + misses, asks Claude to evaluate the
  harness's own performance: which strategies pay off, which
  hypotheses keep missing, where coverage gaps remain. Writes the
  meta-knowledge to <kb>/meta/<date>-critique.md.
  """
  from .agents.critic import self_critique
  result = asyncio.run(self_critique(
    kb_root=kb, model=model, max_turns=max_turns,
  ))
  _console.print(
    f"\n[bold]critique complete[/bold]  turns={result.turns}  "
    f"cost=${result.total_cost_usd:.4f}"
  )
  if result.report_path:
    _console.print(f"  [cyan]> report[/cyan] {result.report_path}")


@main.command()
@click.option(
  "--kb", type=click.Path(exists=True, path_type=Path), required=True,
  help="Knowledge base root.",
)
@click.option(
  "--finding", "finding_id", required=True,
  help="Finding id to mutate (e.g. 2026-04-25-rate-limit-...).",
)
@click.option(
  "--fwl-bin", default=None,
  help="Path to the fwl binary (defaults to PATH).",
)
def mutate(kb: Path, finding_id: str, fwl_bin: str | None) -> None:
  """Loop 3 — Mutate a confirmed finding's PoC for related bugs.

  Runs deterministic mutations (port shifts, proto swap, src_ip
  bump, TCP flag toggles, rate_limit threshold ±1) against the .fw
  + .pkt embedded in a finding. Each mutant runs through both
  oracles; oracle disagreements become related findings, agreed
  mutants are promoted to <kb>/corpus/from_mutation/.
  """
  from .mutation import mutate_finding
  try:
    bin_path = resolve_fwl_bin(fwl_bin)
  except FwlNotFound as exc:
    _console.print(f"[red]{exc}[/red]")
    sys.exit(1)
  result = mutate_finding(finding_id, kb, fwl_bin=bin_path)
  _console.print(
    f"\n[bold]mutate[/bold]  finding={finding_id}  "
    f"mutants={result.total}\n"
    f"  agreed:         {result.agree}\n"
    f"  divergent:      [red bold]{result.divergent}[/red bold]\n"
    f"  compile_failed: {result.compile_failed}\n"
    f"  runner_error:   {result.runner_error}"
  )
  for p in result.findings_written:
    _console.print(f"  [red]> finding[/red] {p}")
  if result.divergent:
    sys.exit(1)


@main.command()
@click.option(
  "--kb", type=click.Path(exists=True, path_type=Path), required=True,
  help="Knowledge base root.",
)
@click.option(
  "--finding", "finding_id", required=True,
  help="Finding id whose PoC packet to replay.",
)
@click.option(
  "--targets", type=click.Path(exists=True, path_type=Path),
  required=True,
  help="Directory of .fw programs to consider as transfer targets.",
)
@click.option(
  "--threshold", type=float, default=0.5,
  help="Minimum jaccard score for a candidate to be in scope.",
)
@click.option(
  "--fwl-bin", default=None,
  help="Path to the fwl binary (defaults to PATH).",
)
def transfer(
  kb: Path, finding_id: str, targets: Path,
  threshold: float, fwl_bin: str | None,
) -> None:
  """Loop 4 — Replay a finding against every .fw with overlapping constructs.

  For each .fw under --targets whose construct signature overlaps
  the parent finding's (jaccard >= --threshold), the parent's PoC
  packet is run through both oracles. Oracle divergences become
  related findings; the .pkt is promoted to <kb>/corpus/from_transfer/.
  """
  from .transfer import transfer_finding
  try:
    bin_path = resolve_fwl_bin(fwl_bin)
  except FwlNotFound as exc:
    _console.print(f"[red]{exc}[/red]")
    sys.exit(1)
  result = transfer_finding(
    finding_id, kb, targets, fwl_bin=bin_path, threshold=threshold,
  )
  _console.print(
    f"\n[bold]transfer[/bold]  finding={finding_id}  "
    f"candidates={result.total_candidates}  "
    f"matched={result.matched}  "
    f"skipped(low score)={result.skipped_low_score}\n"
    f"  divergent: [red bold]{result.divergent}[/red bold]   "
    f"agreed: {result.agreed}"
  )
  for p in result.findings_written:
    _console.print(f"  [red]> finding[/red] {p}")
  if result.divergent:
    sys.exit(1)


@main.command()
@click.option(
  "--kb", type=click.Path(exists=True, path_type=Path), required=True,
  help="Knowledge base root.",
)
@click.option(
  "--c", "ucb_c", type=float, default=None,
  help="UCB1 exploration constant (default sqrt(2)).",
)
def tune(kb: Path, ucb_c: float | None) -> None:
  """Loop 5 — Recompute strategy weights from accumulated runs.

  Reads <kb>/meta/strategy_runs.jsonl, runs UCB1 over per-strategy
  hits/runs, writes new weights to <kb>/meta/strategy_weights.json
  (5% floor per strategy so nothing starves), and appends an entry
  to <kb>/meta/strategy_history.jsonl for auditability.
  """
  from .scheduling import recompute_weights
  import math
  reg = recompute_weights(kb, c=ucb_c if ucb_c is not None else math.sqrt(2))
  if not reg.weights:
    _console.print(
      "[yellow]No strategy runs recorded yet — nothing to tune.[/yellow]"
    )
    return
  _console.print(
    f"\n[bold]tune[/bold]  last_tuned={reg.last_tuned}\n"
  )
  for name in sorted(reg.weights, key=reg.weights.get, reverse=True):
    s = reg.stats.get(name)
    runs = s.runs if s else 0
    hits = s.hits if s else 0
    _console.print(
      f"  {name:<24} weight={reg.weights[name]:.3f}  "
      f"hits/runs={hits}/{runs}"
    )


@main.command()
@click.option(
  "--kb", type=click.Path(exists=True, path_type=Path), required=True,
  help="Knowledge base root.",
)
@click.option(
  "--from", "pool", default=None,
  help="Comma-separated subset to draw from (default: all known).",
)
@click.option(
  "--seed", type=int, default=None,
  help="RNG seed for deterministic draws.",
)
def schedule(kb: Path, pool: str | None, seed: int | None) -> None:
  """Loop 5 — Draw the next strategy proportional to current weights."""
  import random
  from .scheduling import draw_weighted
  rng = random.Random(seed) if seed is not None else None
  pool_list = [s.strip() for s in pool.split(",")] if pool else None
  pick = draw_weighted(kb, strategies=pool_list, rng=rng)
  if pick is None:
    _console.print(
      "[yellow]No strategies registered yet. Record a run first via "
      "the strategies pipeline (or call scheduling.record_run).[/yellow]"
    )
    sys.exit(2)
  print(pick)


@main.command("diff-impact")
@click.option(
  "--repo", type=click.Path(exists=True, path_type=Path), required=True,
  help="Path to the FWL repo (where git diff runs).",
)
@click.option(
  "--base", required=True,
  help="Base ref (e.g. main, HEAD~10) for the diff.",
)
@click.option(
  "--head", default="HEAD",
  help="Head ref for the diff (default: HEAD).",
)
@click.option(
  "--map", "construct_map", type=click.Path(path_type=Path), default=None,
  help="Path to compiler_construct_map.yaml (default: bundled).",
)
def diff_impact_cmd(
  repo: Path, base: str, head: str, construct_map: Path | None,
) -> None:
  """Loop 7 — Map a compiler diff to impacted FWL constructs.

  Suggested follow-up: bias the next `hone schedule` toward
  strategies that exercise the impacted constructs (current scheduler
  doesn't know about constructs yet — printed for manual use).
  """
  from .diff_sensitivity import diff_impact
  imp = diff_impact(repo, base, head, construct_map_path=construct_map)
  _console.print(
    f"\n[bold]diff-impact[/bold]  {imp.base_ref}..{imp.head_ref}\n"
    f"  changed files: {len(imp.changed_files)}\n"
    f"  impacted constructs: "
    f"[cyan]{', '.join(sorted(imp.impacted_constructs)) or '(none)'}[/cyan]"
  )
  if imp.unmapped_files:
    _console.print(
      "  [yellow]unmapped files (consider updating construct map):"
      "[/yellow]"
    )
    for f in imp.unmapped_files[:10]:
      _console.print(f"    - {f}")


@main.command()
@click.option(
  "--kb", type=click.Path(exists=True, path_type=Path), required=True,
  help="Knowledge base root.",
)
@click.option(
  "--window", type=int, default=100,
  help="How many recent disagreements to consider (default: 100).",
)
@click.option(
  "--threshold", type=float, default=0.8,
  help="Same-direction ratio that triggers a bias flag (default 0.8).",
)
def calibrate(kb: Path, window: int, threshold: float) -> None:
  """Loop 8 — Report on systematic oracle disagreement bias."""
  from .calibration import build_report
  r = build_report(kb, window=window, bias_threshold=threshold)
  _console.print(
    f"\n[bold]calibrate[/bold]  window={window}  "
    f"threshold={threshold}\n  total events: {r.total}"
  )
  for direction, n in sorted(r.by_direction.items()):
    _console.print(f"  {direction:<24} {n}")
  if r.flagged_bias:
    _console.print(
      f"\n[red bold]>> systematic bias detected[/red bold]: "
      f"{r.flagged_bias} ({r.ratio:.0%} of directional disagreements)"
    )
  elif r.total >= 5:
    _console.print(
      "\n[green]No systematic bias detected.[/green]"
    )


if __name__ == "__main__":
  main()
