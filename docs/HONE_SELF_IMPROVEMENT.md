# Hone — Self-Improvement Loops

## Context

This document describes eight feedback loops that make hone a learning system rather than a stateless fuzzer. Each loop produces a signal the harness already generates but currently discards. Capturing and acting on these signals is what turns "LLM + fuzzer" into something that compounds.

See `HONE_REPO_DESIGN.md` for the base architecture. See `F_SECURITY_HARNESS.md` for the full vision. This note covers the mechanisms that make the harness get better over time without human intervention.

## Current Learning (Baseline)

The base harness design has three feedback loops:

1. **Miss deduplication.** Past misses prevent the LLM from re-proposing the same hypothesis. Saves API budget.
2. **Pattern abstraction.** Findings cluster into bug classes. Agents receive relevant patterns at round start. Narrows hypothesis generation.
3. **Regression corpus growth.** Every confirmed bug becomes a permanent test. The corpus grows monotonically.

These are necessary but not sufficient. The harness still depends on the LLM's creativity for hypothesis quality, uses fixed strategy weights, and doesn't learn from its own operational performance. The loops below close those gaps.

## Loop 1 — Prompt Evolution

**Signal:** which hypothesis framings correlate with confirmed bugs.

**Mechanism:** after every N rounds, a meta-agent reads the last N hypotheses with their outcomes (hit/miss). It extracts which *framing patterns* in the prompt correlated with hits and rewrites the hypothesis system prompt to emphasize those patterns.

Example: if hypotheses framed as "what happens when field X is at its maximum value while field Y is at its minimum" produce 4× the hit rate of hypotheses framed as "check for integer overflow in X", the meta-agent rewrites the system prompt to emphasize boundary-interaction hypotheses over single-field overflow hypotheses.

The rewritten prompt is versioned in `knowledge-base/meta/prompts/` so the evolution is auditable. Each version records what changed, why, and the hit-rate data that justified the change.

This is prompt-level natural selection. Prompts that find bugs survive; prompts that don't get rewritten.

**When it matters:** after enough data exists to distinguish signal from noise. Probably 200+ hypotheses with outcomes (two to three months of operation).

## Loop 2 — Coverage-Guided Steering

**Signal:** which BPF branches have never been exercised by any test in the corpus.

**Mechanism:** instrument the generated `.bpf.c` with coverage counters. Run the full corpus. Produce a coverage map. Feed the map to the LLM with the instruction: "these branches have never been exercised — generate packets that reach them."

The LLM is good at this — it can read C code and reason about what input reaches a specific branch. The coverage map tells it where to look instead of wandering. After each round, the map updates and the harness steers toward the remaining dark spots.

Implementation options:
- clang's `-fsanitize-coverage=trace-pc-guard` on the generated BPF C (works if compiled to native for testing, not directly for BPF target)
- Manual branch annotation: the FWL compiler emits comments at each branch point; a coverage tracker maps BPF_PROG_RUN results to which branches were taken
- BPF-native: use `bpf_trace_printk` or a dedicated coverage map that the generated program writes to on each branch

The third option is cleanest but adds map overhead to the generated program. A `--coverage` compiler flag that enables it only during hone runs keeps the production path clean.

**When it matters:** immediately useful. Coverage-guided anything outperforms random anything. Build this early.

## Loop 3 — Finding Mutation

**Signal:** a confirmed bug defines a point in packet-space that triggers a failure. The neighborhood of that point likely contains more failures.

**Mechanism:** when a confirmed finding is produced, automatically generate mutants of the PoC packet:

- Vary field values slightly (port 22 → 21, 23, 0, 65535)
- Change the protocol (TCP → UDP, same port values)
- Flip individual bits in the packet
- Extend or truncate the packet by one byte at each layer boundary
- Replay the exact PoC against other `.fw` programs in the target set

Each mutant runs through both oracles. Oracle disagreements on mutants become new findings, grouped under the original as "related." Mutants that all pass map the boundary of the bug — "it breaks at length 19 but not 20."

This is deterministic. No LLM cost. It runs after every confirmed finding.

**When it matters:** immediately. The first confirmed bug triggers the mutation engine and potentially produces several related findings for free.

## Loop 4 — Cross-Program Transfer

**Signal:** a bug found in program A may exist in program B if B uses the same constructs.

**Mechanism:** when a finding is classified, extract its structural signature — which FWL constructs were involved (rate_limit + CIDR + boolean composition), what packet shape triggered it, what the failure mode was. Scan all other target programs for the same construct combination. For each match, generate a targeted test adapting the PoC to the new program's specific rules.

This is the "fix once, check everywhere" loop. A bug found in one firewall gets automatically checked against every other firewall in the target set.

The construct-matching is AST-level, not text-level. The harness parses each target program, builds a set of (construct, field, modifier) tuples, and checks for overlap with the finding's signature. Overlap above a threshold triggers a targeted test round.

**When it matters:** when the harness has multiple target programs. Less useful when testing a single firewall; very useful when testing a fleet of customer configurations.

## Loop 5 — Strategy Weight Auto-Tuning

**Signal:** which discovery strategies produce findings at what cost.

**Mechanism:** the scheduler tracks hits (confirmed findings) and cost (API calls, compute time) per strategy per time window. After each evaluation period (weekly or after N rounds), it updates the strategy weights using a multi-armed bandit algorithm.

```
Strategy             Hits   Cost    Hits/$   Weight (old → new)
boundary_probing      12    $0      ∞        25 → 35
oracle_divergence      8    $0      ∞        15 → 25
hypothesis_driven      3    $45     0.07     30 → 20
differential_spec      1    $0      ∞        10 → 10
stateful_chains        0    $30     0        15 → 5
regression             —    $0      —         5 → 5
```

Algorithm: epsilon-greedy or UCB1. Every strategy gets a minimum floor (5%) so nothing starves permanently. The "explore" arm occasionally runs the worst-performing strategy to check whether circumstances have changed (new code, new target programs, new patterns).

The weight history is logged in `knowledge-base/meta/strategy_weights.json` so the evolution is visible.

**When it matters:** after a few weeks of operation, once the per-strategy hit rates are statistically distinguishable.

## Loop 6 — Embedding Cluster Detection

**Signal:** findings clustering in embedding space means the harness is stuck in a local optimum.

**Mechanism:** after each round, compute the centroid of recent finding embeddings (last 30 days). Compute the average distance from each finding to the centroid. If the average distance drops below a threshold, the harness is producing findings that are all "about the same thing."

When clustering is detected, trigger a forced exploration round. The exploration prompt explicitly avoids the dominant cluster: "generate hypotheses that are NOT about [dominant pattern]. Focus on [least-explored protocol / construct / code region]."

Least-explored is computed from the coverage map (loop 2) or from the knowledge base — which protocols, built-ins, and construct combinations have the fewest findings?

This is diversity pressure. It prevents the harness from spending three months finding variations of the same off-by-one while ignoring entire unexplored regions.

**When it matters:** when the knowledge base has 50+ findings. Before that, there's not enough data to detect clustering meaningfully.

## Loop 7 — Compiler Diff Sensitivity

**Signal:** which parts of the compiler just changed.

**Mechanism:** the harness watches the `fwl` compiler repo (git webhook or periodic poll). When a new commit lands, it:

1. Parses the diff.
2. Maps changed files/functions to FWL constructs (e.g., `emitter/rate_limit.py` → rate_limit, `emitter/bounds_check.py` → all field access).
3. Boosts the strategy weights for the affected constructs for the next N rounds.
4. Optionally runs a targeted round: only test programs that use the affected constructs, only hypotheses about the affected constructs.

The mapping from compiler source files to FWL constructs is a static configuration (maintained by hand, updated when compiler structure changes):

```yaml
# config/compiler_construct_map.yaml
emitter/rate_limit.py: [rate_limit]
emitter/bounds_check.py: [pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.tcp.syn, pkt.tcp.ack]
emitter/boolean.py: [and, or, not]
parser/grammar.py: [all]
semantic/protocol_guard.py: [protocol_guards]
```

This is change-aware testing. The harness focuses on what just changed rather than re-testing everything uniformly.

**When it matters:** when the compiler is actively evolving (v0.2 development and beyond). Less useful during v0.1 stabilization when the compiler is frozen.

## Loop 8 — Oracle Self-Calibration

**Signal:** systematic directional bias in oracle disagreements.

**Mechanism:** when the oracles disagree, the harness records not just that they disagreed but which direction:

```
disagreement_log:
  - test: boundary_tcp_truncated_19.pkt
    interpreter: drop
    bpf: allow
    direction: interpreter_stricter
  - test: rate_limit_concurrent_cpu.pkt
    interpreter: drop
    bpf: allow
    direction: interpreter_stricter
```

Periodically (weekly), compute the ratio. If 80%+ of disagreements go the same direction, that's a systematic bias in one oracle. The harness flags it:

"19 of 23 oracle disagreements this month had the interpreter returning `drop` while BPF returned `allow`. The interpreter may be more conservative than the compiled code for [construct X]. Manual review recommended."

This doesn't auto-fix anything — oracle bugs require human judgment. But it surfaces patterns a human would miss by looking at individual disagreements in isolation.

**When it matters:** nice-to-have. The interpreter is simple enough that bugs in it are rare. This loop becomes more useful as the interpreter and compiler grow in complexity through v0.2+.

## Implementation Priority

Ordered by value-per-effort:

| Priority | Loop | Effort | Payoff | LLM cost |
|---|---|---|---|---|
| 1 | **Strategy auto-tuning** (5) | Small — bandit over existing metrics | Immediate budget optimization | None |
| 2 | **Finding mutation** (3) | Small — deterministic packet mangling | Free findings from every confirmed bug | None |
| 3 | **Cross-program transfer** (4) | Medium — AST matching + test adaptation | Scales findings across the target set | None |
| 4 | **Coverage-guided steering** (2) | Medium — instrumentation + coverage map | Biggest long-term improvement | Minimal |
| 5 | **Prompt evolution** (1) | Medium — meta-agent + prompt versioning | Better hypothesis quality over time | Moderate |
| 6 | **Compiler diff sensitivity** (7) | Small — diff parser + construct map | Change-aware testing | None |
| 7 | **Embedding cluster detection** (6) | Small — distance computation + threshold | Prevents local optima | None |
| 8 | **Oracle self-calibration** (8) | Small — ratio tracking + alerting | Catches interpreter drift | None |

For hone v0.1: build loops 5, 3, and 4. They're cheap, deterministic, and immediately useful.

For hone v0.2: add loops 2 and 1. Coverage-guided steering and prompt evolution require more data and more infrastructure but produce the biggest quality improvements.

Loops 6, 7, and 8 add when the system is mature enough to benefit — 50+ findings, active compiler development, enough oracle disagreements to detect patterns.

## The Compound Effect

None of these loops is individually revolutionary. The compound effect is what matters:

- Loop 3 (mutation) finds the neighborhood of a bug.
- Loop 4 (transfer) checks the neighborhood across all programs.
- Loop 5 (auto-tuning) allocates more budget to the strategies that found the original bug.
- Loop 2 (coverage) steers toward the code regions the mutations didn't reach.
- Loop 1 (prompt evolution) adjusts the hypothesis generator based on what worked.
- Loop 6 (clustering) detects when the system is stuck and forces exploration.

After six months of operation, the harness has: an optimized budget allocation, a hypothesis generator tuned to the specific bug classes this codebase exhibits, a coverage map showing which regions still need attention, a mutation engine that extracts maximum value from every confirmed finding, and a diversity mechanism that prevents stagnation.

That's a system that improves along six axes simultaneously without human intervention. The human's job is reduced to: review confirmed findings, fix the bugs, and occasionally check that the self-improvement mechanisms are producing sensible results.
