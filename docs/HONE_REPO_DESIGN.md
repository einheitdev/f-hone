# hone — Adversarial Security Harness

## Repository Design

This document specifies the repo layout, components, and startup path for `hone`, the adversarial AI security harness for FWL programs. See `F_SECURITY_HARNESS.md` for the full vision; this document is the implementation plan.

## Three Repos

```
github.com/KRuskowski/fwl               # the compiler (exists)
github.com/KRuskowski/hone          # this repo — the harness tooling
github.com/KRuskowski/f-knowledge-base   # findings, misses, patterns, corpus
```

**fwl** is the compiler. The harness calls it via subprocess (`fwl compile`, `fwl interpret`) and imports its packet builder for BPF_PROG_RUN. The harness does not modify the compiler; it exercises it.

**hone** is the tooling: controller, agent pods, Solr integration, indexing pipeline, discovery strategies. Python. Depends on `fwl` being installed.

**f-knowledge-base** is a data repo. Markdown findings, `.pkt` corpus files, pattern docs. No code. Version-controlled, diffable, publishable. The harness reads from it (via Solr index) and writes to it (new findings, new corpus entries). The public-facing security website renders from this repo.

Keeping the knowledge base separate means:
- Operators can fork it for their own deployments without forking the harness code
- The knowledge base has its own access control (you might want outside contributors for pattern review)
- The harness can be pointed at any knowledge base directory — local clone, remote, or empty for first run
- Git history of the knowledge base is pure data; no code churn mixed in

## hone Repo Layout

```
hone/
├── README.md
├── pyproject.toml                      # packaging, deps
├── Makefile                            # convenience targets
│
├── harness/
│   ├── __init__.py
│   ├── cli.py                          # entry points: hone fuzz|hunt|index|report
│   │
│   ├── controller/
│   │   ├── __init__.py
│   │   ├── scheduler.py                # round scheduling, budget tracking
│   │   ├── dispatcher.py               # pod lifecycle management
│   │   └── watcher.py                  # git hook / inotify on .fw files
│   │
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── pod.py                      # agent pod: hypothesis → test → execute → classify
│   │   ├── hypothesis.py               # LLM prompt construction for hypothesis generation
│   │   ├── packet_craft.py             # hypothesis → .pkt file via LLM + scapy
│   │   ├── classifier.py              # oracle results → finding | miss classification
│   │   └── prompts/
│   │       ├── hypothesis_system.txt   # system prompt for hypothesis generation
│   │       ├── packet_craft_system.txt # system prompt for packet crafting
│   │       ├── pattern_abstraction.txt # system prompt for periodic pattern extraction
│   │       └── self_critique.txt       # system prompt for meta-review
│   │
│   ├── oracles/
│   │   ├── __init__.py
│   │   ├── interpreter.py             # calls fwl interpret, parses output
│   │   ├── bpf_runner.py              # calls fwl's BPF_PROG_RUN harness
│   │   └── spec_checker.py            # protocol spec validation (RFC-based)
│   │
│   ├── strategies/
│   │   ├── __init__.py
│   │   ├── oracle_divergence.py       # strategy 1: random packets, compare oracles
│   │   ├── boundary_probing.py        # strategy 2: deterministic boundary testing
│   │   ├── hypothesis_driven.py       # strategy 3: LLM hypothesis generation
│   │   ├── differential_spec.py       # strategy 4: compare against reference parsers
│   │   ├── stateful_chains.py         # strategy 5: multi-packet attack sequences
│   │   └── regression.py              # strategy 6: run corpus, no discovery
│   │
│   ├── retrieval/
│   │   ├── __init__.py
│   │   ├── solr_client.py             # query interface for agent context retrieval
│   │   ├── indexer.py                 # git → parse markdown → compute embedding → Solr update
│   │   ├── embeddings.py              # sentence-transformer embedding computation
│   │   └── schema.py                  # Solr schema definition (fields, types, vector config)
│   │
│   ├── knowledge/
│   │   ├── __init__.py
│   │   ├── finding.py                 # Finding dataclass, markdown serialization
│   │   ├── miss.py                    # Miss dataclass, markdown serialization
│   │   ├── pattern.py                 # Pattern dataclass, markdown serialization
│   │   ├── writer.py                  # write finding/miss/pattern to knowledge base dir
│   │   └── reader.py                  # read + parse from knowledge base dir
│   │
│   └── reporting/
│       ├── __init__.py
│       ├── console.py                 # terminal output for findings
│       ├── github_issues.py           # auto-open issues for confirmed bugs
│       └── stats.py                   # cost tracking, bugs-per-month, coverage
│
├── docker/
│   ├── Dockerfile.harness             # harness + deps (no BPF — for controller + agents)
│   ├── Dockerfile.bpf                 # BPF execution env (ubuntu + clang + CAP_BPF)
│   ├── Dockerfile.solr                # Solr with custom schema
│   └── docker-compose.yml             # full stack: harness + solr + bpf runner
│
├── config/
│   ├── harness.yaml                   # default configuration
│   └── solr/
│       └── managed-schema.xml         # Solr schema with vector field
│
├── tests/
│   ├── test_classifier.py
│   ├── test_indexer.py
│   ├── test_hypothesis.py
│   ├── test_pod_loop.py
│   └── fixtures/
│       ├── sample_finding.md
│       ├── sample_miss.md
│       └── sample_fw/
│           └── simple_firewall.fw
│
└── scripts/
    ├── setup_solr.sh                  # initialize Solr core with schema
    ├── reindex_knowledge_base.sh      # full reindex from git
    └── install_hooks.sh               # install git hooks in knowledge base repo
```

## f-knowledge-base Repo Layout

```
f-knowledge-base/
├── README.md
├── findings/
│   └── (empty initially — harness populates)
├── misses/
│   └── (empty initially)
├── patterns/
│   └── (empty initially)
├── corpus/
│   └── (seeded from fwl's existing 62-case corpus)
├── triage/
│   ├── fixed/
│   ├── false-positive/
│   ├── wontfix/
│   └── duplicate/
├── stats/
│   └── (harness writes summary stats here)
├── meta/
│   └── (agent self-critique output, scheduler tuning)
└── hooks/
    └── post-commit                    # triggers Solr reindex
```

## Dependencies

```toml
# pyproject.toml [project.dependencies]
[project]
name = "hone"
requires-python = ">=3.11"

dependencies = [
  "anthropic",               # Claude API for agent pods
  "pyyaml",                  # .pkt and config parsing
  "scapy",                   # packet construction for hypothesis testing
  "pysolr",                  # Solr client
  "sentence-transformers",   # embedding computation for vector search
  "rich",                    # terminal output
  "click",                   # CLI framework
  "watchdog",                # filesystem watching for .fw changes
  "gitpython",               # knowledge base git operations
]

[project.optional-dependencies]
dev = [
  "pytest",
  "pytest-cov",
]
```

The harness assumes `fwl` is installed and on PATH (the FWL compiler from the `fwl` repo). It calls `fwl compile`, `fwl interpret`, and `fwl test` as subprocesses.

For BPF_PROG_RUN execution, the harness needs either:
- A local machine with CAP_BPF (the dev VM you already have running)
- A remote BPF execution service (SSH to the VM, run there)
- The Docker BPF container with `--privileged`

## Configuration

```yaml
# config/harness.yaml

# Knowledge base location
knowledge_base:
  path: ../f-knowledge-base            # local clone
  auto_commit: true                     # commit findings/misses automatically
  auto_push: false                      # don't push to remote without review

# FWL compiler
fwl:
  binary: fwl                           # on PATH
  # or: binary: /home/karl/fwl/.venv/bin/fwl

# BPF execution
bpf:
  mode: local                           # local | ssh | docker
  # For ssh mode:
  # ssh_host: worker@192.168.122.47
  # ssh_key: ~/.ssh/id_ed25519_targets
  # For docker mode:
  # image: hone-bpf:latest

# Solr
solr:
  url: http://localhost:8983/solr/hone
  core: hone

# Embeddings
embeddings:
  model: all-MiniLM-L6-v2              # sentence-transformer model
  # or: provider: anthropic             # use Claude embeddings API
  cache_dir: .cache/embeddings

# Agent configuration
agents:
  model: claude-sonnet-4-20250514
  max_tokens: 4096
  pods: 4                              # parallel agent pods
  budget_per_round: 50                  # max API calls per pod per round
  round_timeout: 300                    # seconds per round

# Discovery strategy weights (sum to 100)
strategies:
  oracle_divergence: 15
  boundary_probing: 25
  hypothesis_driven: 30
  differential_spec: 10
  stateful_chains: 15
  regression: 5                         # always runs, weight is for discovery time allocation

# Budget
budget:
  daily_api_limit: 500                  # max Claude API calls per day
  daily_cost_limit: 50.00               # USD, estimated from token usage
  alert_threshold: 0.8                  # warn at 80% of daily limit

# Targets — .fw files to test
targets:
  - path: ../fwl/examples/*.fw          # glob
  - path: ../fwl/tests/corpus/*.fw      # compiler's own test programs
  # Future: customer rule repos
```

## CLI Interface

```bash
# Install
pip install -e .

# Commands
hone fuzz [--strategy boundary_probing] [--target path.fw] [--rounds 10]
  # Deterministic fuzzing — no LLM, no API cost
  # Boundary probing, oracle divergence with random packets, regression

hone hunt [--pods 4] [--budget 50] [--target path.fw]
  # LLM-assisted discovery — hypothesis generation, context retrieval, full loop
  # This is the expensive one

hone regress [--corpus path/to/corpus/]
  # Run the full regression corpus — no discovery, just verification
  # CI target

hone index [--full] [--path ../f-knowledge-base]
  # (Re)index the knowledge base into Solr
  # --full: delete and rebuild from scratch
  # Default: incremental, only changed files

hone report [--format console|json|markdown] [--since 7d]
  # Summary of findings, coverage, cost
  # Reads from knowledge base + Solr

hone abstract [--min-findings 5]
  # Run the pattern abstraction pass
  # Reads all findings, proposes pattern documents, writes drafts to knowledge base

hone critique [--round-id X]
  # Run the self-critique pass on a completed round
  # Writes meta-knowledge to knowledge base
```

## The Agent Pod Loop (Detail)

This is the core of `hone hunt`. Each pod runs this loop:

```python
class AgentPod:
  def run_round(self, target_fw: Path, budget: int):
    # 1. Load target
    source = target_fw.read_text()
    compiled_c = self.fwl_compile(target_fw)  # .bpf.c output

    # 2. Retrieve context from knowledge base via Solr
    features = self.extract_features(source)  # protocols, builtins, patterns
    context = self.solr.query(
      protocols=features.protocols,
      builtins=features.builtins,
      exclude_status=["false-positive", "duplicate"],
      limit=20,
    )

    # 3. Generate hypotheses
    for i in range(budget):
      hypothesis = self.llm_generate_hypothesis(
        source=source,
        compiled_c=compiled_c,
        context=context,
        past_hypotheses=self.round_hypotheses,  # avoid repeats within round
      )

      if hypothesis.is_duplicate(context.past_misses):
        self.record_skip(hypothesis, reason="already_tested")
        continue

      # 4. Craft test packet from hypothesis
      pkt_file = self.llm_craft_packet(hypothesis)

      # 5. Execute against oracles
      interp_result = self.oracle_interpret(target_fw, pkt_file)
      bpf_result = self.oracle_bpf(target_fw, pkt_file)

      # 6. Classify
      if interp_result != bpf_result:
        # Oracle divergence — compiler bug
        finding = self.create_finding(
          hypothesis, pkt_file, interp_result, bpf_result,
          classification="compiler_bug",
        )
        self.kb.write_finding(finding)
        self.kb.write_corpus(pkt_file)

      elif interp_result != hypothesis.expected:
        # Both oracles agree, but disagree with hypothesis
        miss = self.create_miss(hypothesis, interp_result)
        self.kb.write_miss(miss)

      elif interp_result == hypothesis.expected:
        # Hypothesis confirmed — but what does "confirmed" mean?
        # If hypothesis.expected was "bug behavior", this IS a bug
        if hypothesis.expects_bug:
          finding = self.create_finding(
            hypothesis, pkt_file, interp_result, bpf_result,
            classification=hypothesis.bug_class,
          )
          self.kb.write_finding(finding)
          self.kb.write_corpus(pkt_file)
        else:
          # Hypothesis was "this should work correctly" and it does
          # Not interesting — skip
          pass

      self.round_hypotheses.append(hypothesis)
```

## Solr Setup

Solr runs as a Docker container or local install. One core, custom schema:

```xml
<!-- config/solr/managed-schema.xml (key fields) -->
<field name="id" type="string" indexed="true" stored="true" required="true"/>
<field name="type" type="string" indexed="true" stored="true"/>        <!-- finding|miss|pattern -->
<field name="protocol" type="strings" indexed="true" stored="true"/>   <!-- [tcp, udp, wg, ...] -->
<field name="builtins" type="strings" indexed="true" stored="true"/>   <!-- [rate_limit, geoip, ...] -->
<field name="severity" type="string" indexed="true" stored="true"/>    <!-- low|medium|high|critical -->
<field name="layer" type="string" indexed="true" stored="true"/>       <!-- user_rule|compiler|builtin -->
<field name="pattern_tags" type="strings" indexed="true" stored="true"/>
<field name="status" type="string" indexed="true" stored="true"/>      <!-- open|fixed|false-positive -->
<field name="summary" type="text_general" indexed="true" stored="true"/>
<field name="body" type="text_general" indexed="true" stored="true"/>
<field name="embedding" type="knn_vector" indexed="true" stored="true"
       vectorDimension="384" vectorEncoding="FLOAT32" similarityFunction="cosine"/>
<field name="created" type="pdate" indexed="true" stored="true"/>
<field name="source_file" type="string" indexed="true" stored="true"/> <!-- which .fw file -->
```

The `embedding` field uses Solr's built-in dense vector support (available since Solr 9.x). Dimension 384 matches `all-MiniLM-L6-v2`; adjust if using a different model.

## Indexing Pipeline

```
knowledge base git repo
     │
     │  post-commit hook (or hone index --incremental)
     │
     ▼
  Parse changed .md files
     │
     ├─ Extract front-matter fields (type, protocol, severity, etc.)
     ├─ Extract body text
     ├─ Compute embedding: sentence_transformer.encode(summary + body[:500])
     │
     ▼
  Solr atomic update
     │
     └─ upsert document by id
```

Front-matter format in knowledge base markdown files:

```markdown
---
id: finding/2026-04-18-wg-truncate
type: finding
protocol: [wg, udp]
builtins: [wg_valid_size]
severity: medium
layer: builtin
pattern_tags: [claimed-vs-actual-length]
status: fixed
source_file: examples/wg_relay.fw
created: 2026-04-18
---

# 2026-04-18-wg-truncate

## Summary
wg_valid_size accepts type-1 packets of 148 bytes even when...
```

The front-matter is YAML between `---` markers (standard Jekyll/Hugo convention). The indexer parses it, extracts the fields, computes the embedding from the title + summary section, and sends the whole thing to Solr.

## Startup Path

### Week 1: Infrastructure

- Create both repos (`hone`, `f-knowledge-base`)
- Set up pyproject.toml with dependencies
- Docker compose: Solr container with custom schema
- `hone index` command: parse knowledge base markdown → Solr
- Seed `f-knowledge-base/corpus/` from fwl's existing 62 test cases
- Verify: index round-trips (write markdown → index → query → get it back)

### Week 2: Deterministic Fuzzing

- `hone fuzz` with strategy: boundary_probing
- Oracle wrappers: call `fwl interpret` and parse output
- Oracle wrappers: call BPF_PROG_RUN on the VM via SSH
- Finding/miss writers: create markdown, commit to knowledge base
- Run against fwl's example programs
- Goal: find at least one real boundary issue (there will be one)

### Week 3: Regression Runner

- `hone regress` runs the full corpus
- Exits non-zero if any test fails
- Wire into CI (GitHub Actions or local pre-push hook)
- Fast enough to run on every commit (should be seconds for 62 cases)

### Week 4: LLM Agent Pod

- `hone hunt` with one pod
- Hypothesis generation prompt with Solr context injection
- Packet craft prompt → `.pkt` file
- Oracle execution → classification → finding or miss
- End-to-end: one hypothesis, tested, classified, written to knowledge base
- Budget tracking: count API calls, estimate cost

### Week 5+: Scale and Harden

- Multi-pod parallel execution
- Strategy rotation (scheduler picks strategy based on weights)
- Pattern abstraction pass (`hone abstract`)
- Self-critique pass (`hone critique`)
- GitHub issue auto-creation for confirmed findings
- Cost reporting (`hone report`)

## Relationship to fwl_test_agent.py

`fwl_test_agent.py` (the tool you just built) generates test cases for the FWL compiler's own test suite during language development. It's a developer tool that lives in the `fwl` repo.

`hone` tests programs written in FWL — user firewalls, G-generated rules, fleet policies. It finds bugs in the programs, in the compiler, and in built-ins. It's an infrastructure service that runs continuously.

They share:
- The `.pkt` file format
- The oracle mechanism (interpreter + BPF_PROG_RUN)
- The Claude API for test generation

They differ in:
- Scope: `fwl_test_agent` tests the language; `hone` tests everything
- Lifecycle: `fwl_test_agent` runs when you're developing; `hone` runs 24/7
- Knowledge: `fwl_test_agent` is stateless; `hone` accumulates institutional knowledge via Solr
- Human in the loop: `fwl_test_agent` generates tests you review; `hone` triages autonomously and escalates findings

The corpus generated by `fwl_test_agent` can be seeded into `f-knowledge-base/corpus/` as the initial regression baseline. The harness benefits from those tests; they become the floor.

## Cost Estimate (Phase 1-2)

| Component | Monthly cost | Notes |
|---|---|---|
| Solr | $0 | Runs on your dev VM |
| Sentence-transformer | $0 | Local model, CPU inference |
| Claude API (fuzz) | $0 | Deterministic strategies, no LLM |
| Claude API (hunt) | $50-150 | 4 pods × ~100 calls/day × $0.01-0.03/call |
| BPF VM | $0 | Already running (fwl-test VM) |
| Knowledge base hosting | $0 | GitHub repo |
| Total | $50-150/month | |

Phase 1 (deterministic fuzzing) costs nothing beyond compute time. Phase 2 (LLM-assisted) adds the API cost. The knowledge base starts paying back in Phase 2 by reducing duplicate hypotheses.
