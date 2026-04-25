"""Pretty-printers for harness output, using rich for color/formatting."""
from __future__ import annotations

from rich.console import Console
from rich.table import Table

from ..knowledge.types import Finding
from ..oracles.bpf_runner import CorpusVerdict


def format_corpus_results(verdict: CorpusVerdict, console: Console) -> None:
  """Print a summary table of one `hone regress` / `fwl test` run."""
  if not verdict.cases:
    console.print(
      f"[yellow]No .pkt cases found "
      f"(exit {verdict.invocation.exit_code}).[/yellow]"
    )
    if verdict.invocation.stderr:
      console.print(verdict.invocation.stderr)
    return

  table = Table(
    title=(
      f"corpus verdict: {verdict.passed}/{verdict.total} passed"
    ),
    show_lines=False,
  )
  table.add_column("status")
  table.add_column("case")
  table.add_column("oracles")
  table.add_column("detail")

  for case in verdict.cases:
    if case.passed:
      status = "[green]PASS[/green]"
    else:
      status = "[red]FAIL[/red]"
    oracles = " ".join(
      _color_oracle(name, st) for name, st in case.oracles.items()
    )
    detail = "; ".join(
      f"{name}: {text[:70]}"
      for name, text in case.details.items()
      if case.oracles.get(name) not in ("pass",)
    )
    table.add_row(status, case.pkt_file, oracles, detail)

  console.print(table)
  if not verdict.all_passed:
    console.print(
      f"[red bold]{verdict.total - verdict.passed} case(s) "
      f"need triage[/red bold]"
    )


def _color_oracle(name: str, status: str) -> str:
  """Compact colored badge for one oracle's status in a table cell."""
  color = {
    "pass": "green",
    "skip": "yellow",
    "fail": "red",
    "error": "red bold",
  }.get(status, "white")
  return f"[{color}]{name}={status}[/{color}]"


def format_finding(finding: Finding, console: Console) -> None:
  """Single-finding summary block. Used by `hone hunt` once it lands."""
  console.print(
    f"\n[bold red]Finding[/bold red] {finding.id}  "
    f"[{finding.severity.value}/{finding.layer.value}]"
  )
  console.print(f"  {finding.summary}")
  if finding.pattern_tags:
    console.print(
      f"  [dim]patterns: {', '.join(finding.pattern_tags)}[/dim]"
    )
  if finding.pkt_path:
    console.print(f"  [dim]pkt: {finding.pkt_path}[/dim]")
