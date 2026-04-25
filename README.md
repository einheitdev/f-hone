# hone

Adversarial AI security harness for FWL programs. Runs continuously against
the FWL compiler and the firewall rules it produces, looking for bugs in
three layers: user rule programs, the compiler itself, and built-ins.

Sister project to [`fwl`](https://github.com/KRuskowski/fwl) (the compiler)
and [`f-knowledge-base`](https://github.com/KRuskowski/f-knowledge-base)
(the findings/corpus/patterns repo). See `docs/HONE_REPO_DESIGN.md` and
`docs/F_SECURITY_HARNESS.md` for the full design.

## Status (early scaffold)

| Subsystem | Status |
|---|---|
| CLI shell | scaffolded (most subcommands stub) |
| Knowledge writer/reader (markdown + YAML frontmatter) | working |
| Oracle wrappers (subprocess to `fwl`) | working |
| `hone regress` (run a corpus, report) | working |
| `hone fuzz` (deterministic strategies) | not implemented |
| `hone hunt` (LLM agent pods + Solr context) | not implemented |
| Solr index + indexing pipeline | not implemented |
| Docker compose for the stack | not implemented |

The first useful command is `hone regress` — runs a `.pkt` corpus through
all three FWL oracles and reports per-case verdict. No LLM, no Solr.

## Install

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

Requires `fwl` (the compiler) installed and on PATH. By default `hone`
looks for `fwl` in `$PATH`; override with `--fwl-bin`.

## Quick start

```sh
hone regress --corpus ../f/fwl/tests/corpus/
hone --help
```

## Layout

```
hone/
  harness/                  Python package
    cli.py                  Click entry points
    controller/             Daemon, scheduler, dispatcher (deferred)
    agents/                 Agent pod loop, prompts (deferred)
    oracles/                Subprocess wrappers around `fwl`
    strategies/             Discovery strategies (deferred)
    retrieval/              Solr client + indexer (deferred)
    knowledge/              Finding/Miss/Pattern dataclasses + markdown IO
    reporting/              Console + GitHub issue reporters
  config/                   harness.yaml + Solr schema
  docker/                   Dockerfiles + compose (deferred)
  tests/                    Unit + fixtures
  scripts/                  Setup / reindex helpers
```

## Relationship to `fwl-test-agent`

`fwl-test-agent` (in the FWL repo) generates test cases for the FWL
compiler's own development corpus. It's a developer tool: stateless,
runs when you're working on the language.

`hone` is the long-running production harness. It tests user rule
programs *and* the compiler, accumulates institutional knowledge in a
git-backed knowledge base, and produces a regression corpus that grows
monotonically over time. The `.pkt` format and the oracle mechanism are
shared; everything else is different.

## Authentication

Like `fwl-test-agent`, `hone` uses [`claude-code-sdk`](https://pypi.org/project/claude-code-sdk/)
so LLM calls are authenticated through your existing Claude Code session
(subscription) rather than an API key.
