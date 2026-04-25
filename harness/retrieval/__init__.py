"""Solr-backed retrieval over the knowledge base.

Markdown findings/misses/patterns get indexed into Solr (structured
fields + a dense vector embedding) so agent pods can pull the 15-20
most relevant prior items into their LLM context — instead of
re-discovering the same bugs every round.

Not yet implemented — needs Solr running. See docs/HONE_REPO_DESIGN.md
section "Solr Setup" and "Indexing Pipeline" for the schema and flow.
"""
