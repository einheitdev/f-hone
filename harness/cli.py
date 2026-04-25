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


if __name__ == "__main__":
  main()
