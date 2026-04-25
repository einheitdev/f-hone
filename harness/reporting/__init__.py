"""Output channels for findings.

Currently: console (rich-formatted summary). Planned: GitHub issue
auto-creation, daily/weekly stats reports, RSS feed for the public
knowledge base.
"""
from .console import format_corpus_results, format_finding

__all__ = ["format_corpus_results", "format_finding"]
