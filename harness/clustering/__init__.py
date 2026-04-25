"""Loop 6 — Embedding cluster detection (DEFERRED, embeddings pending).

Per HONE_SELF_IMPROVEMENT.md loop 6: compute the centroid of recent
finding embeddings (last 30 days). When the average distance from
each finding to the centroid drops below a threshold, the harness
is in a local optimum — trigger a forced exploration round that
explicitly avoids the dominant cluster.

This is a stub. The infrastructure prerequisite is sentence-
transformers (or a remote embedding API) integration:

  1. Pick an embedding model. The current stack uses Solr 9 with
     no embeddings; bringing them in means installing the
     `sentence-transformers` Python package (heavyweight; ~1.5GB)
     OR adding a Solr knn_vector field and pre-computing embeddings
     server-side on index.

  2. Re-index the kb with embeddings populated from each finding's
     summary + body text.

  3. A clustering reader: read recent embeddings, compute centroid +
     average distance, compare to threshold. Returns `dominant
     pattern` slug and a list of "least-explored" surfaces.

  4. The forced-exploration round: a specialised hone hunt prompt
     that names the cluster to avoid + the surfaces to explore.

The doc says "wait until 50+ findings before this is statistically
useful." Tracking as v0.2 — see docs/HONE_SELF_IMPROVEMENT.md.
"""


class NotYetImplementedError(NotImplementedError):
  """Deliberate deferral marker."""
  pass


def detect_cluster(*args, **kwargs):
  """Placeholder for the embedding-space clustering check."""
  raise NotYetImplementedError(
    "Loop 6 (embedding cluster detection) is deferred to hone v0.2. "
    "See harness/clustering/__init__.py for the prerequisites."
  )
