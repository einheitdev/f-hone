"""Knowledge-base -> Solr indexing pipeline.

Walks a knowledge-base directory, parses each finding/miss/pattern
markdown file via the knowledge.reader module, and upserts a Solr
document per file. Idempotent: re-running with no changes is a
no-op (Solr dedups on `id`).

Embedding fields are intentionally not produced — vector search lands
when sentence-transformers integration arrives. Until then, retrieval
is structured + full-text only, which is plenty for the early
volume of findings.
"""
from __future__ import annotations
from datetime import date, datetime
from pathlib import Path
from typing import Iterable

from ..knowledge.reader import scan_knowledge_base
from ..knowledge.types import Finding, Miss, Pattern
from .solr_client import SolrClient


def _date_to_solr(d: date | datetime | None) -> str | None:
  """Solr's pdate field wants a strict ISO 8601 instant."""
  if d is None:
    return None
  if isinstance(d, datetime):
    return d.isoformat() + "Z"
  return f"{d.isoformat()}T00:00:00Z"


def _doc_for_finding(f: Finding) -> dict:
  """Map Finding -> Solr document matching the schema."""
  return {
    "id": f"finding/{f.id}",
    "type": "finding",
    "protocol": list(f.protocols),
    "builtins": list(f.builtins),
    "severity": f.severity.value,
    "layer": f.layer.value,
    "pattern_tags": list(f.pattern_tags),
    "status": f.status,
    "summary": f.summary,
    "body": f.body,
    "source_file": f.source_file,
    "pkt_path": f.pkt_path,
    "created": _date_to_solr(f.created),
  }


def _doc_for_miss(m: Miss) -> dict:
  """Map Miss -> Solr document."""
  return {
    "id": f"miss/{m.id}",
    "type": "miss",
    "protocol": list(m.protocols),
    "builtins": list(m.builtins),
    "pattern_tags": list(m.pattern_tags),
    "summary": m.hypothesis,
    "body": m.body,
    "source_file": m.source_file,
    "created": _date_to_solr(m.created),
  }


def _doc_for_pattern(p: Pattern) -> dict:
  """Map Pattern -> Solr document."""
  return {
    "id": f"pattern/{p.id}",
    "type": "pattern",
    "protocol": list(p.protocols),
    "summary": p.description,
    "body": p.body,
    "created": _date_to_solr(p.created),
  }


def reindex(
  kb_root: Path,
  client: SolrClient,
  full: bool = False,
) -> dict:
  """Walk the kb and upsert every entity.

  When `full=True`, drops the entire core first so deletes propagate.
  Returns counts: {"findings": N, "misses": N, "patterns": N}.
  """
  if full:
    client.delete_by_query("*:*")
  findings, misses, patterns = scan_knowledge_base(kb_root)
  docs = (
    [_doc_for_finding(f) for f in findings]
    + [_doc_for_miss(m) for m in misses]
    + [_doc_for_pattern(p) for p in patterns]
  )
  client.upsert_many(docs, commit=True)
  return {
    "findings": len(findings),
    "misses": len(misses),
    "patterns": len(patterns),
    "total": len(docs),
  }


def query_relevant(
  client: SolrClient,
  protocols: Iterable[str] = (),
  builtins: Iterable[str] = (),
  exclude_status: Iterable[str] = ("false-positive", "duplicate"),
  rows: int = 20,
) -> list[dict]:
  """Pull the most-relevant prior findings/misses/patterns for a target.

  Used by agents at round start: filter by protocols/builtins seen in
  the target program, exclude triaged-out items, return Solr docs.
  Vector search via embeddings will ride alongside this once it lands.
  """
  fq: list[str] = []
  for proto in protocols:
    fq.append(f"protocol:{proto}")
  for builtin in builtins:
    fq.append(f"builtins:{builtin}")
  for status in exclude_status:
    fq.append(f"-status:{status}")
  return client.search(
    q="*:*",
    fq=fq or None,
    rows=rows,
    sort="created desc",
  )
