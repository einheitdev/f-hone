"""Aggregate stats over a knowledge base for `hone report`.

Walks <kb>/{findings,misses,patterns}/*.md, buckets entities by
status / severity / layer / protocol / pattern_tag / created-day, and
renders the result either as a rich console table or as JSON for
downstream tooling.
"""
from __future__ import annotations
import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path

from rich.console import Console
from rich.table import Table

from ..knowledge.reader import scan_knowledge_base


@dataclass
class ReportStats:
  """Snapshot of one `hone report` run."""
  kb_root: str = ""
  cutoff: str | None = None
  total_findings: int = 0
  total_misses: int = 0
  total_patterns: int = 0
  findings_by_status: dict[str, int] = field(default_factory=dict)
  findings_by_severity: dict[str, int] = field(default_factory=dict)
  findings_by_layer: dict[str, int] = field(default_factory=dict)
  findings_by_protocol: dict[str, int] = field(default_factory=dict)
  findings_by_pattern: dict[str, int] = field(default_factory=dict)
  findings_by_day: dict[str, int] = field(default_factory=dict)
  misses_by_protocol: dict[str, int] = field(default_factory=dict)
  patterns_by_size: dict[str, int] = field(default_factory=dict)
  uncovered_findings: list[str] = field(default_factory=list)


def build_report(kb: Path, cutoff: date | None = None) -> ReportStats:
  """Walk the knowledge base and bucket entities for a report."""
  kb = kb.resolve()
  findings, misses, patterns = scan_knowledge_base(kb)

  if cutoff is not None:
    findings = [f for f in findings if f.created >= cutoff]
    misses = [m for m in misses if m.created >= cutoff]
    patterns = [p for p in patterns if p.created >= cutoff]

  stats = ReportStats(
    kb_root=str(kb),
    cutoff=cutoff.isoformat() if cutoff else None,
    total_findings=len(findings),
    total_misses=len(misses),
    total_patterns=len(patterns),
  )

  by_status = Counter(f.status for f in findings)
  by_sev = Counter(f.severity.value for f in findings)
  by_layer = Counter(f.layer.value for f in findings)
  by_proto = Counter(p for f in findings for p in (f.protocols or []))
  by_pat = Counter(t for f in findings for t in (f.pattern_tags or []))
  by_day = Counter(f.created.isoformat() for f in findings)
  miss_proto = Counter(p for m in misses for p in (m.protocols or []))
  pat_sizes = Counter(
    str(len(p.known_instances or [])) for p in patterns
  )
  tagged_ids = {
    f.id for f in findings
    if any(
      f.id in (p.known_instances or []) for p in patterns
    ) or f.pattern_tags
  }
  uncovered = sorted(f.id for f in findings if f.id not in tagged_ids)

  stats.findings_by_status = dict(by_status)
  stats.findings_by_severity = dict(by_sev)
  stats.findings_by_layer = dict(by_layer)
  stats.findings_by_protocol = dict(by_proto)
  stats.findings_by_pattern = dict(by_pat)
  stats.findings_by_day = dict(sorted(by_day.items()))
  stats.misses_by_protocol = dict(miss_proto)
  stats.patterns_by_size = dict(pat_sizes)
  stats.uncovered_findings = uncovered
  return stats


def render_json(stats: ReportStats) -> str:
  """Stable JSON dump — sorted keys for deterministic CI diffs."""
  return json.dumps(asdict(stats), sort_keys=True, indent=2)


def render_console(stats: ReportStats, console: Console) -> None:
  """Rich table layout, one section per bucket dimension."""
  scope = (
    f"since {stats.cutoff}" if stats.cutoff else "all-time"
  )
  console.print(
    f"\n[bold]hone report[/bold]  kb={stats.kb_root}  ({scope})\n"
  )
  console.print(
    f"  findings: [red bold]{stats.total_findings}[/red bold]"
    f"   misses: {stats.total_misses}"
    f"   patterns: {stats.total_patterns}\n"
  )

  if stats.total_findings == 0:
    console.print("[dim]No findings in scope yet.[/dim]")
    return

  console.print(_count_table(
    "findings by status", stats.findings_by_status,
  ))
  console.print(_count_table(
    "findings by severity", stats.findings_by_severity,
    order=("critical", "high", "medium", "low"),
  ))
  console.print(_count_table(
    "findings by layer", stats.findings_by_layer,
  ))
  if stats.findings_by_protocol:
    console.print(_count_table(
      "findings by protocol", stats.findings_by_protocol,
    ))
  if stats.findings_by_pattern:
    console.print(_count_table(
      "findings by pattern_tag", stats.findings_by_pattern,
    ))
  if stats.findings_by_day:
    console.print(_count_table(
      "findings by day", stats.findings_by_day,
      order=tuple(sorted(stats.findings_by_day.keys())),
    ))
  if stats.uncovered_findings:
    console.print(
      f"\n[yellow]uncovered findings (no pattern_tag, no pattern "
      f"reference):[/yellow] {len(stats.uncovered_findings)}"
    )
    for fid in stats.uncovered_findings[:10]:
      console.print(f"  - {fid}")
    if len(stats.uncovered_findings) > 10:
      console.print(
        f"  [dim]... and {len(stats.uncovered_findings) - 10} more[/dim]"
      )


def _count_table(
  title: str,
  counts: dict[str, int],
  order: tuple[str, ...] | None = None,
) -> Table:
  """Two-column count table sorted by count desc unless `order` set."""
  table = Table(title=title, show_header=True, show_lines=False)
  table.add_column("key")
  table.add_column("count", justify="right")
  if order is not None:
    rows = [(k, counts.get(k, 0)) for k in order if k in counts]
  else:
    rows = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
  for k, v in rows:
    table.add_row(k, str(v))
  return table
