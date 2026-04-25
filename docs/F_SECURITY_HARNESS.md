# f — Adversarial AI Security Harness

## Overview

An autonomous harness that continuously searches for security bugs in f — in user rule programs, in the FWL compiler itself, and in the generated BPF. It runs 24/7, generates attack hypotheses, crafts test packets, verifies behavior against two independent oracles, and reports findings. Over time it builds institutional knowledge about what kinds of bugs exist, how to find them, and how to classify them — knowledge that outlives any single agent run or model version.

The harness is not a replacement for human security review. It is a force multiplier. A solo developer cannot match the breadth of an always-on adversarial process. The harness finds the obvious bugs and the subtle patterns; the human triages, fixes, and decides what matters.

## Goals

1. **Find bugs automatically.** Logic errors in rule programs, semantic mismatches between FWL source and compiled BPF, memory-safety issues in generated code, off-by-ones in protocol parsers, state-machine violations in stateful primitives.

2. **Build institutional knowledge.** Every bug found, every hypothesis tested (whether it hit or missed), every classification decision becomes structured knowledge the harness reuses. The harness gets better over time, not through model improvements alone but through accumulated domain-specific insight.

3. **Create a regression corpus.** Bugs become tests. Tests never get removed. The corpus grows monotonically. Every commit runs against the full corpus before any new search begins.

4. **Publish the process.** Findings, methodology, and the knowledge base are public artifacts. This is a trust signal for security-conscious users who want to see how the product is tested.

## Oracles

The hardest part of automated bug-finding is the oracle problem — how does the system know a result is a bug? For f, we have two independent oracles that answer this without human judgment.

### Oracle 1 — Semantic Equivalence

Two implementations of the same spec should produce the same output for the same input:

- **AST interpreter** evaluates the `.fw` source directly in Python. Slow but correct-by-construction.
- **BPF_PROG_RUN** executes the compiled BPF bytecode. The real production code path.

For any test packet, both must return the same action (drop/allow/pass/redirect) and the same counter updates. If they disagree, exactly one of them is wrong. In almost all cases it's the compiled BPF (compiler bug) because the AST interpreter is simple enough to inspect visually.

### Oracle 2 — Protocol Specification

For built-in validators like `wg_valid_size(pkt)` or TCP parsing, the protocol spec is the oracle. RFC 793 says the TCP header is 20 bytes minimum, with options extending it. A test packet with a 14-byte "TCP header" must be rejected. If the f parser accepts it, that's a bug.

Protocol specs covered:
- IPv4 (RFC 791), IPv6 (RFC 8200)
- TCP (RFC 793, 9293)
- UDP (RFC 768)
- ICMP (RFC 792, 4443)
- WireGuard (the informal spec + reference implementation)

### Oracle 3 — Rule Intent (weak, LLM-assisted)

When the bug is in the user's rule program, the oracle is the user's intent. "I wrote `drop if src_ip in geoip('RU')`, did that actually drop all Russian traffic?" This oracle is weak because intent is in the user's head. The LLM approximates it by reading the rule + comments + test cases, and flagging cases where the rule's natural-language meaning appears violated. High false-positive rate; findings need human triage.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   Harness Controller                            │
│                                                                 │
│   Git hook on commit  ─▶  Queue new .fw files                  │
│                                                                 │
│   Scheduler:                                                    │
│     - Regression run: full corpus against new commit           │
│     - Discovery run: agent pods search for new bugs            │
│     - Periodic: revisit past findings, check for regressions   │
│                                                                 │
│   Isolation: each test in a fresh BPF test environment         │
│   (lightweight VM or container with CAP_BPF)                   │
└─────────────────────────────┬───────────────────────────────────┘
                              │
       ┌──────────────────────┼──────────────────────┐
       ▼                      ▼                      ▼
 ┌───────────┐          ┌───────────┐          ┌───────────┐
 │ Agent Pod │          │ Agent Pod │          │ Agent Pod │
 │     1     │          │     2     │   ...    │     N     │
 │           │          │           │          │           │
 │  LLM      │          │  LLM      │          │  LLM      │
 │  Packet   │          │  Packet   │          │  Packet   │
 │  Craft    │          │  Craft    │          │  Craft    │
 │  Test     │          │  Test     │          │  Test     │
 └─────┬─────┘          └─────┬─────┘          └─────┬─────┘
       │  ▲                   │  ▲                   │  ▲
       │  │ relevant          │  │                   │  │
       │  │ findings +        │  │                   │  │
       │  │ misses + patterns │  │                   │  │
       │  │                   │  │                   │  │
       │  └───────────┬───────┴──┴───────────────────┘  │
       │              │                                  │
       │      ┌───────┴────────────┐                     │
       │      │  Solr (retrieval)  │                     │
       │      │                    │                     │
       │      │  - facet search    │                     │
       │      │  - vector search   │                     │
       │      │  - ms latency      │                     │
       │      └───────▲────────────┘                     │
       │              │ index update on commit           │
       │              │                                  │
       └──────────────┼──────────────────────────────────┘
                      ▼
                ┌─────────────────────────────┐
                │    Knowledge Base (git)     │
                │                             │
                │  - Findings (markdown)      │
                │  - Hypotheses (tried+missed)│
                │  - Bug patterns             │
                │  - Regression corpus (.pkt) │
                │  - Triage decisions         │
                └─────────────────────────────┘
```

### Harness Controller

Long-running daemon. Responsibilities:

- Watch `.fw` files in the repository, trigger runs on change.
- Schedule agent pods. A typical run has 4-16 pods in parallel.
- Provide each pod with isolated BPF execution environment (fresh network namespace + CAP_BPF, or a VM per pod for stronger isolation).
- Collect findings, deduplicate against the knowledge base, file structured bug reports.
- Track budget: API calls, compute hours, cost per finding.

### Agent Pods

Each pod is an LLM-backed process with a specific mandate: "find bugs in this `.fw` file using this budget of API calls and this time limit."

Agent pod loop:

```
1. Read inputs:
   - Target .fw source
   - Generated .bpf.c
   - types.h (struct layouts)
   - Relevant spec fragments (from knowledge base)
   - Related past findings (from knowledge base)
   - Bug patterns seen in similar programs (from knowledge base)

2. Generate hypothesis (LLM):
   Natural-language description of a possible bug, including:
   - The suspected cause (off-by-one, missing bounds check, 
     logical inconsistency, state violation)
   - The class of attack (structure, behavioral, semantic)
   - The expected behavior vs actual behavior

3. Translate to test (LLM + scapy):
   - Craft the specific packet or packet sequence
   - Specify preconditions (rate limiter state, conntrack state,
     map contents)
   - Specify expected outcome at each oracle

4. Execute:
   - Run AST interpreter against the test
   - Run BPF_PROG_RUN against the test
   - Compare outcomes, compare against spec expectation

5. Classify:
   - If both oracles agree with hypothesis → likely bug
   - If oracles disagree with each other → compiler bug
   - If oracles agree but disagree with hypothesis → 
     hypothesis was wrong; record as tried-and-missed
   - If all agree → hypothesis falsified, record and move on

6. Report:
   - Bug: structured finding with PoC, classification, severity
   - Miss: hypothesis + why it was wrong (for knowledge base)

7. Commit to knowledge base, feed back into next iteration.
```

### Knowledge Base

A git repository. Structured markdown files. Version-controlled, diffable, publishable.

Structure:

```
knowledge-base/
├── findings/                    # confirmed bugs, one per file
│   ├── 2026-04-18-wg-truncate.md
│   ├── 2026-04-19-tcp-options-overflow.md
│   └── ...
├── misses/                      # hypotheses that were wrong
│   ├── 2026-04-18-ip-frag-dos.md
│   └── ...
├── patterns/                    # abstracted bug patterns
│   ├── off-by-one-in-length-field.md
│   ├── missing-guard-on-optional-header.md
│   ├── state-map-race-on-concurrent-update.md
│   └── ...
├── corpus/                      # regression test packets
│   ├── 2026-04-18-wg-truncate.pkt
│   └── ...
├── triage/                      # human decisions on findings
│   ├── fixed/
│   ├── false-positive/
│   ├── wontfix/
│   └── duplicate/
└── stats/
    ├── bugs-per-month.json
    ├── cost-per-finding.json
    └── coverage.json
```

The knowledge base is the institutional memory. It is the thing that makes this a learning system instead of a stateless fuzzer.

## Institutional Knowledge: The Learning Loop

This is the part that makes the harness valuable long-term. Without it, the harness is just fuzzing with extra steps. With it, the harness becomes a compounding asset — every day it runs, it gets better at finding bugs because it accumulates domain-specific insight that model training cannot provide.

### What Knowledge Looks Like

**Finding records (what bugs exist):**

```markdown
# 2026-04-18-wg-truncate

## Summary
wg_valid_size accepts type-1 packets of 148 bytes even when the
actual payload is truncated to <148 bytes by the outer transport.

## Root Cause
The check compares `pkt.wg.payload_len` (claimed) against the type
constants, not `pkt.udp.len - 8` (actual). An attacker can claim
148 bytes but deliver 100.

## Classification
- Pattern: claimed-vs-actual-length
- Layer: protocol parser
- Severity: medium (DoS — relay forwards garbage to peers which drop it)

## PoC
See corpus/2026-04-18-wg-truncate.pkt

## Fix
Add `pkt.udp.len - 8 == pkt.wg.payload_len` check.
Merged in commit abc123.

## Related
- patterns/claimed-vs-actual-length.md
- findings/2025-...-similar-issue-in-tcp.md
```

**Miss records (what was tried and didn't work):**

```markdown
# 2026-04-18-ip-frag-dos

## Hypothesis
IP fragmentation could cause the L4 offset calculation to read
past the packet buffer, triggering a verifier rejection at load
time or a runtime bounds-check failure.

## Test
Sent a fragmented TCP SYN with offset=0x1FFF.

## Result
BPF program correctly handled it — the frag offset check in the
IP parser catches this case. No bug.

## Why Recorded
Future agents might propose the same hypothesis. Recording the
miss saves the API calls. Also useful context: "how did we
protect against this class?" is answered by the miss record
linking to the existing check.
```

**Patterns (abstracted bug classes):**

```markdown
# claimed-vs-actual-length

## Description
Protocols with a length field in the header can be attacked by
delivering a packet where the claimed length differs from the
actual length. Parsers that trust the claimed length read past
buffer boundaries; parsers that trust the actual length miss
malformed packets.

## Check Strategy
For every protocol with a length field, verify that:
1. Claimed length matches actual length (within delta for alignment)
2. Claimed length is within sane bounds for the protocol
3. Both checks happen before any field access using the length

## Known Instances
- findings/2026-04-18-wg-truncate.md (WireGuard)
- findings/2025-11-02-ip-total-length.md (IPv4)
- findings/2025-09-15-tcp-data-offset.md (TCP)

## Where to Look Next
- ICMP length field
- ESP/AH header lengths
- Any custom protocol in inline_c blocks
```

### How Knowledge Feeds Back

When an agent starts a new round on a `.fw` file, it doesn't start blank. It receives:

- **Relevant past findings** — bugs found in similar rules, or in this same rule before.
- **Applicable patterns** — if the rule uses `pkt.tcp.*`, the agent receives the TCP-related patterns. If it uses custom `inline_c`, it receives the memory-safety patterns.
- **Past misses on this file** — hypotheses that were already falsified. Don't waste API calls re-testing them.
- **Known-good checks** — the agent knows which defenses are already in place, so it doesn't rediscover them.

This context is included in the LLM prompt. The model's general reasoning + the domain-specific context = targeted hypothesis generation.

The mechanism that makes this work at scale is the retrieval backend below. Without it, the feedback loop is theoretical — the knowledge base is a pile of markdown files the LLM can't efficiently consult. With it, every agent round starts with the 15-20 most relevant past findings already surfaced.

### Retrieval Backend (Solr)

The knowledge base lives as markdown files in git. For humans browsing, that's the right format. For agents querying, markdown is useless — grepping thousands of files per round won't work, and shoving everything into the LLM context won't either (cost + context length).

A retrieval layer bridges the two. Solr is the right choice because the findings are structured text with natural fields — protocol, rule pattern, severity, affected function, PoC bytes. Solr's faceted search and field-weighted queries map to exactly the kinds of questions an agent needs to ask. Add embedding fields for semantic similarity and you get both precise and fuzzy retrieval in one system.

**Index structure:**

Each finding, miss, and pattern is indexed as a Solr document with fields like:

```
id:              finding/2026-04-18-wg-truncate
type:            finding | miss | pattern
protocol:        [tcp, udp, wg, ipv4, ipv6, icmp]
built_ins:       [rate_limit, conntrack, geoip, wg_valid_size]
severity:        low | medium | high | critical
layer:           user_rule | compiler | builtin
pattern_tags:    [claimed-vs-actual-length, off-by-one]
status:          open | fixed | false-positive
summary:         <short text>
body:            <full markdown>
embedding:       <vector, 768-dim from sentence transformer>
created:         2026-04-18
```

The embedding field is computed once per document from the summary + body and stored in a dense vector field. Solr supports k-nearest-neighbor queries over vector fields alongside regular keyword search.

**Retrieval at round start:**

When an agent pod begins a round on a `.fw` file, the controller:

1. Extracts features from the rule: protocols used (`pkt.tcp.*` → tcp), built-ins called (`rate_limit` → rate_limit), control flow shape (nested conditionals, tail calls, etc.).

2. Constructs a Solr query combining structured filters and semantic search:

```
# Structured filter
q: (protocol:tcp OR protocol:udp) AND built_ins:rate_limit
fq: NOT status:false-positive
fq: NOT status:duplicate

# Semantic boost
knn: embedding_field LIKE rule_summary_embedding

# Sort
sort: score desc, severity desc, created desc
rows: 20
```

3. Returns the top 20 results — mix of exact-match findings (structured) and semantically-similar ones (vector). Plus the patterns those findings cluster into.

4. Injects a summarized version into the LLM's context: "Here are 15 bugs found in similar rules. Here are 4 patterns abstracted from them. Here are 3 hypotheses that were tried on similar rules and falsified (don't re-propose them)."

**Query cost:** milliseconds. **Context cost:** 2-5K extra tokens per round. **Value:** the LLM is no longer reasoning from scratch. It reasons from "here's what has actually broken in this codebase." That narrows hypothesis generation from "everything I know about security" to "everything I know plus the specific failure modes this system has exhibited."

**Why this matters for economics:**

Stateless LLM-driven fuzzing suffers from a specific failure mode: the model repeatedly proposes the same hypotheses. Each run is independent. It can't remember that two weeks ago it tried "what if the IP length field overflows" and the oracles said no. It proposes it again. And again. API budget burns on rediscovery.

Retrieval-augmented fuzzing escapes this loop. The LLM sees past misses. The model either skips them or proposes variations that get around the defenses documented in the miss records. Misses are as valuable as findings for retrieval — they represent what has already been tested and found safe. Without them, the harness spends forever rediscovering that the same attacks still don't work.

Rough economics after the knowledge base matures (say, 100+ indexed findings and 50+ misses):

| Metric | Stateless | Retrieval-augmented |
|---|---|---|
| Hypothesis hit rate | 5-10% | 20-30% |
| API cost per round | Same | Same (+5% for context) |
| API cost per confirmed bug | $X | ~$X/3-5 |
| Novel findings (non-rediscovery) | Mixed | Higher |
| Coverage of subtle bugs | Low | Better |

The retrieval layer pays for itself within the first few weeks of operation. The infrastructure cost is negligible — Solr runs on the same VM as the harness controller, memory footprint is maybe 500MB for 10K findings, query latency is a few milliseconds.

**Indexing pipeline:**

Every time a finding, miss, or pattern is committed to the knowledge-base git repo, a post-commit hook indexes it:

```
git commit → hook fires → read changed markdown files →
  parse front-matter fields + body →
  compute embedding (sentence-transformer API or local model) →
  Solr update
```

The index stays in sync with the git repo. Recovery from index loss is straightforward: delete the Solr index, walk the git history, reindex everything. The git repo is the source of truth; Solr is a derived view.

**Federation implications:**

When multiple f operators run their own harnesses (Phase 5), each has its own local Solr index over their own findings. Shared patterns can be published back to the central knowledge base, which the central Solr indexes. Operators can query the central index for patterns before their agents run, getting the benefit of fleet-wide bug discovery without sharing their specific findings.

**Retrieval as a public API:**

The public knowledge base website (Phase 3) can expose the Solr query interface directly. Security researchers auditing f can query "show me all findings related to protocol parsers" and get a structured list. This is more useful than browsing markdown files and again serves as a trust signal — the knowledge is organized, searchable, and verifiable.

### Pattern Abstraction (the critical move)

Individual findings are useful. Patterns are more useful. The harness should periodically abstract from findings to patterns.

Mechanism: after N findings accumulate, run a specific LLM pass that reads all findings and proposes pattern abstractions. The output is a draft `patterns/*.md` file. A human reviews it, edits if needed, and merges.

Example: after finding bugs in WG length validation, TCP data-offset validation, and IPv4 total-length validation, the pattern "claimed-vs-actual-length" emerges. The pattern document is more valuable than any of the individual findings because it points forward — the next agent knows to check ESP, AH, GRE, and any custom protocol for the same class.

The pattern abstraction is what turns "a fuzzer that found 50 bugs" into "a security methodology that understands 10 classes of bugs." The first is a list. The second is a science.

### Agent Self-Critique

After each run, a dedicated agent pod reviews what was found and what was missed:

- Did we find many bugs of type X? The pattern exists; create or update its doc.
- Did we propose many hypotheses of type Y and all miss? The pattern's check is already in place; document the defense.
- Are we spending API budget on low-yield hypotheses? Update the scheduler to deprioritize them.

This is meta-knowledge: knowledge about how the harness itself should operate. It goes into `knowledge-base/meta/` and influences future scheduler decisions.

### Publication

The knowledge base is public. Users of f can read:

- What bugs have been found
- What patterns the harness knows about
- What defenses are in place
- How much compute has been spent looking

This is a trust artifact. A prospective user asking "how do I know f is secure?" gets a concrete answer: "Here are the 247 findings we've triaged, the 23 patterns we've abstracted, the 180,000 hypotheses tested, and the corpus of regression tests." That's more useful than a security whitepaper.

## Discovery Strategies

Different strategies for different bug classes. The scheduler rotates through them.

### Strategy 1 — Oracle Divergence

Craft random-ish packets, feed to both oracles, look for disagreement.

- Cheap, parallelizable, finds compiler bugs.
- Heavy on API budget but high yield early in f's lifecycle.
- Decays over time as obvious divergences get fixed.

### Strategy 2 — Boundary Probing

For every length field, every flag, every optional header, test the boundaries: 0, 1, max, max-1, max+1, overflow.

- Deterministic, doesn't need an LLM (this is Level 1).
- Finds off-by-ones, unchecked overflows, missing bounds.
- Should be part of every regression run, not just discovery.

### Strategy 3 — Hypothesis-Driven (LLM)

LLM reads the source + context, proposes specific attacks based on what it knows about similar code.

- Expensive per hypothesis but high signal.
- Best for subtle bugs that deterministic fuzzing misses.
- Improves as the knowledge base grows.

### Strategy 4 — Differential Against Specs

For each protocol, the harness has a reference implementation (e.g., scapy for packet construction, the Linux kernel's own parsers). Test f's parse output against the reference.

- Finds parser bugs where f deviates from canonical behavior.
- Requires maintaining the reference list as protocols are added.

### Strategy 5 — Stateful Attack Chains

Individual packets are easy. Multi-packet sequences that exploit stateful primitives (rate_limit windows, conntrack state transitions, map race conditions under concurrent access) are harder.

- LLM generates sequences, harness replays them.
- Oracle is harder — the expected behavior depends on the sequence.
- High-value target class because it's what a real attacker would do.

### Strategy 6 — Regression (Not Discovery)

Run the full corpus against every commit. Not looking for new bugs; ensuring old bugs don't come back. Cheap, fast, runs in CI on every push.

## Budget and Economics

Rough numbers for a one-developer project:

| Component | Cost | Notes |
|---|---|---|
| LLM API (discovery) | $30-100/day | 4 pods, Claude Sonnet tier |
| Compute (BPF test env) | $20-50/month | One cloud VM, CAP_BPF enabled |
| Storage (knowledge base) | Free | Git repo |
| Human triage time | 1-2 hrs/week | Review findings, merge fixes |

So roughly $1-3k/month in variable cost plus 8 hours/week of your time. The cost-per-bug-found drops as the knowledge base matures — early bugs are expensive to find because the harness is blind; later bugs are cheap because the harness knows where to look.

A reasonable target: 5-10 real bugs per month after the first 3 months of operation. At $3k/month, that's $300-600 per confirmed bug. Market rate for manual security review is $200-500/hour; a bug found by a human auditor costs 2-10 hours of their time = $400-5000. The harness is cheaper per bug once it's mature, and it runs while you sleep.

## Scope of Findings

The harness targets three layers. Budget is allocated across them based on risk.

### Layer 1 — User Rule Programs (`.fw` files)

Bugs are in the operator's rules: logic errors, missing checks, unintended interactions between rules. High frequency, low severity individually (one user's broken rule doesn't compromise other users). These are primarily useful for the user writing the rule, not for f's maintainer.

Suggested budget: 20%.

### Layer 2 — The FWL Compiler

Bugs are in the compiler itself: incorrect C emission, missing bounds checks in generated code, wrong byte-order conversions, verifier-failing outputs for valid input. Lower frequency, high severity — a compiler bug affects every user. These are the "find once, fix globally" class.

Suggested budget: 60%.

### Layer 3 — Built-in Functions and Runtime

Bugs are in `rate_limit`, `conntrack`, `geoip`, `wg_valid_size`, the BPF map primitives themselves, the orchestrator daemon. Medium frequency, high severity — built-ins are used by every rule program, so bugs are widely felt.

Suggested budget: 20%.

## Phases

### Phase 1 — Level 1 Harness (deterministic)

No LLM. Pure rule-based fuzzing:
- Boundary probing on every length field
- Structure validation against protocol specs
- Oracle divergence with randomized packets
- Regression corpus execution

Deliverable: `fwl fuzz` command that runs continuously, reports findings to the knowledge base directory as plain findings (no AI-generated hypothesis text yet).

Builds the infrastructure without the LLM cost. Proves out the oracle mechanism and the knowledge base structure. Catches the low-hanging fruit.

### Phase 2 — Level 2 Harness (LLM-assisted)

Add LLM-backed agent pods:
- Hypothesis generation with context from knowledge base
- Structured finding reports
- Pattern abstraction passes (weekly)
- Self-critique passes (monthly)

Deliverable: `fwl hunt` command that runs agent pods with a budget, integrates with an LLM API, produces rich findings with PoCs.

Adds depth. Catches the subtle bugs that deterministic fuzzing misses. Starts building real institutional knowledge.

### Phase 3 — Public Knowledge Base

The knowledge base becomes a public artifact:
- Git repo on GitHub
- Rendered as a website (mdBook or similar)
- Cross-linked: findings link to patterns, patterns link to corpus entries
- RSS feed for new findings (security-conscious users can subscribe)

Deliverable: `security.hyper-derp.dev` or similar. Publishing the knowledge is the trust signal.

### Phase 4 — Continuous Integration

The harness runs on every commit:
- Full regression corpus in CI (must pass before merge)
- Discovery run on PRs that touch the compiler or built-ins
- Nightly deep discovery run against main branch
- Automatic PR opening when the harness finds + verifies a bug (with proposed fix if the LLM is confident)

Deliverable: GitHub Actions workflow that gates merges on security regression and opens issues for new findings.

### Phase 5 — Federated Intelligence

Multiple operators run their own f deployments. Each has its own knowledge base, with its own findings specific to their rules. An opt-in mechanism lets operators share anonymized findings back to the central knowledge base.

- Operator finds a bug in their custom rule set. Pattern is applicable to others.
- Anonymized pattern upstream. Other operators' harnesses see it, check their own rules, find their own instances.
- The knowledge compounds across the user base, not just within one deployment.

Deliverable: federation protocol (probably just a signed JSON-over-HTTPS submission). Opt-in, privacy-preserving, mutually beneficial.

## Risks and Limitations

**LLM hallucination.** The LLM will propose "bugs" that aren't bugs. Mitigation: the oracle layer catches these automatically — the LLM's hypothesis has to produce a concrete PoC packet, and if the oracles don't confirm it, it's filed as a miss, not a finding. False-positive findings that reach human triage should be rare; when they happen, they go into `triage/false-positive/` and the harness learns the pattern to avoid it.

**Coverage bias.** The harness finds bugs it knows how to look for. It cannot find bugs in classes it hasn't been taught about. Mitigation: periodic manual review by a human who can spot systemic blind spots. If the harness has never flagged anything in, say, the timer subsystem, that's either "no bugs" or "no coverage." Investigate which.

**Adversarial feedback.** If the knowledge base is public, an attacker can read it to understand what f checks for and what it doesn't. Mitigation: this is fine, actually. The defenses are in the code, not in the secrecy of the check list. An attacker who reads the knowledge base learns "f already catches X, Y, Z" and has to attack something else. Security through transparency.

**API cost runaway.** An agent pod in a loop that keeps generating similar hypotheses without learning burns money. Mitigation: budget caps per pod per run, similarity detection on hypotheses (reject near-duplicates before sending to LLM), scheduler deprioritizes low-yield strategies.

**Knowledge base poisoning.** If someone submits false findings or misleading patterns, the harness learns wrong things. Mitigation: federation is signed and opt-in; central knowledge base only accepts from trusted sources; all automated updates go through git and are auditable.

**Regression loss.** If the knowledge base's git history is corrupted or lost, institutional knowledge is gone. Mitigation: the knowledge base is a git repo; back it up like any other critical repo. Publish to multiple remotes.

## Why This Matters

Traditional security review is a snapshot. You pay $50-150k for an audit, you get a report, the bugs are fixed, and then the code keeps changing and new bugs appear that the report doesn't cover. Three years later you pay for another audit.

The AI harness is continuous. Every commit is reviewed. Every pattern abstracted becomes permanent coverage. The knowledge base is a living document that reflects the current understanding of what can go wrong.

For an open-source infrastructure project run by one person, this is the only way to have meaningful security coverage. You cannot out-audit a well-funded competitor. You can out-automate them. Cilium has a team of paid engineers doing security work. You have an always-on harness that never takes a break, never forgets, and gets cheaper per bug as it learns.

That's the asymmetric advantage.

## The Pitch

> f is continuously fuzzed by an AI harness that runs 24/7. Every bug found is published, every test case is permanent, every pattern discovered is documented. The security knowledge base is public, signed, and grows with every commit. You can read it. Your auditor can read it. Your procurement team can cite it.
>
> Most infrastructure software ships with "we take security seriously" in the README. f ships with 50,000 hours of automated adversarial testing, a public corpus of 10,000 regression tests, and 23 documented bug patterns with known instances and mitigations.
>
> Which one do you trust?
