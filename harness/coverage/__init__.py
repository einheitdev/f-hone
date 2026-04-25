"""Loop 2 — Coverage-guided steering (DEFERRED, instrumentation pending).

Per HONE_SELF_IMPROVEMENT.md loop 2: instrument the generated BPF C
with branch counters, run the full corpus, produce a coverage map,
hand the unexercised branches to the LLM as targeted hunt directives.

The doc lists three implementation options; the cleanest is BPF-
native — a dedicated coverage map written from the generated
program on each branch. That requires:

  1. A `--coverage` flag on the FWL emitter that wraps every emitted
     branch with `__sync_fetch_and_add(&fwl_cov_map[id], 1)` and
     declares an extra map. Should NOT change behavior; only counts.

  2. A coverage reader on the userspace side that reads the map and
     produces `branch_id -> hit_count` for one or many BPF_PROG_RUN
     invocations.

  3. A branch-id allocator the emitter shares with a sidecar table
     (`branch_id -> source_location`) so hone can render coverage
     gaps in terms a human / LLM can act on ("interpreter.py:91 has
     never been hit by any test in the corpus").

  4. A CLI: `hone coverage --kb <kb> --corpus <dir>` that runs the
     corpus, drains the coverage map, and emits a report.

The doc rates this "biggest long-term improvement". Tracking as
v0.2 — coverage instrumentation belongs upstream in the FWL
compiler, not in hone.
"""


class NotYetImplementedError(NotImplementedError):
  """Deliberate deferral marker."""
  pass


def coverage_report(*args, **kwargs):
  """Placeholder for the coverage map reader + reporter."""
  raise NotYetImplementedError(
    "Loop 2 (coverage-guided steering) is deferred to hone v0.2. "
    "See harness/coverage/__init__.py for the prerequisites."
  )
