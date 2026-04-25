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
import sys
from pathlib import Path

import click
from rich.console import Console

from . import __version__
from .oracles.bpf_runner import run_corpus
from .oracles.fwl_subprocess import FwlNotFound, resolve_fwl_bin
from .reporting.console import format_corpus_results


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
def fuzz() -> None:
  """Deterministic discovery (boundary / oracle-divergence)."""
  _not_yet("fuzz")


@main.command()
def hunt() -> None:
  """LLM agent pods + Solr-augmented hypothesis generation."""
  _not_yet("hunt")


@main.command()
def index() -> None:
  """Re-index the knowledge base into Solr."""
  _not_yet("index")


@main.command()
def report() -> None:
  """Summary of findings, coverage, cost."""
  _not_yet("report")


@main.command()
def abstract() -> None:
  """Pattern abstraction pass over accumulated findings."""
  _not_yet("abstract")


@main.command()
def critique() -> None:
  """Self-critique pass — what worked, what didn't, what to tune."""
  _not_yet("critique")


if __name__ == "__main__":
  main()
