"""Discovery strategies.

Each strategy is one approach to finding bugs:
  - oracle_divergence  random-ish packets, compare oracles
  - boundary_probing   deterministic boundary value testing
  - hypothesis_driven  LLM-generated targeted hypotheses
  - differential_spec  compare against reference implementations (scapy)
  - stateful_chains    multi-packet attack sequences
  - regression         run the corpus, no discovery (CI target)

Only `regression` is implemented today; the others are deferred.
"""
