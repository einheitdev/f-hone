"""Knowledge-base entities (Finding, Miss, Pattern) + markdown IO.

The knowledge base is a git repo of markdown files with YAML
frontmatter. This package handles the round-trip between dataclasses
and on-disk markdown so the rest of the harness never touches files
directly.
"""
from .types import Finding, Miss, Pattern, Severity, Layer
from .reader import read_finding, read_miss, read_pattern, scan_knowledge_base
from .writer import write_finding, write_miss, write_pattern

__all__ = [
  "Finding", "Miss", "Pattern", "Severity", "Layer",
  "read_finding", "read_miss", "read_pattern", "scan_knowledge_base",
  "write_finding", "write_miss", "write_pattern",
]
