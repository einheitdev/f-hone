"""Agent pod — claude-code-sdk driven bug hunt.

Adapted from fwl-test-agent's --explore mode. Each pod is one
multi-turn Claude session with Read/Bash/Write tools enabled, given
a target .fw file (or directory) and a knowledge-base root, and told
to find bugs using the hypothesis -> test -> classify loop from
F_SECURITY_HARNESS.md.

The pod writes findings/misses/corpus directly to the kb (via Bash:
`hone` is on PATH, but the agent typically just writes markdown
files directly using the format spec in HONE_REPO_DESIGN.md).

Auth piggybacks on the user's Claude Code subscription — no API
key, no separate billing. Same workaround as fwl-test-agent for
unknown event types in the SDK.
"""
from __future__ import annotations
import time
from dataclasses import dataclass
from pathlib import Path

from .features import extract_from_path

try:
  from claude_code_sdk import (
    AssistantMessage,
    ClaudeCodeOptions,
    ResultMessage,
    TextBlock,
    query,
  )
  from claude_code_sdk._internal import client as _sdk_client
  from claude_code_sdk._internal import message_parser
  from claude_code_sdk._internal.message_parser import MessageParseError
  from claude_code_sdk.types import StreamEvent
except ImportError as exc:
  raise ImportError(
    "claude-code-sdk not installed. Run: pip install claude-code-sdk"
  ) from exc


_original_parse = message_parser.parse_message


def _patched_parse(data):
  """Same workaround as fwl-test-agent: swallow unknown event types
  (rate_limit_event, etc.) so the stream doesn't crash mid-response."""
  try:
    return _original_parse(data)
  except MessageParseError:
    return StreamEvent(
      uuid=data.get("uuid", ""),
      session_id=data.get("session_id", ""),
      event=data,
      parent_tool_use_id=data.get("parent_tool_use_id"),
    )


message_parser.parse_message = _patched_parse
_sdk_client.parse_message = _patched_parse


_DEFAULT_MODEL = "claude-opus-4-7"


_HUNT_SYSTEM_PROMPT = """You are a security agent hunting for bugs
in FWL programs and the FWL compiler. You have full Read/Bash/Write
access from the working directory.

Your goal each round: find programs and packets where the FWL
implementation does the wrong thing, where "wrong" means:

A. The interpreter and the BPF runtime disagree on the action for
   the same packet (compiler bug — most common).
B. The analyzer accepts a program the spec says is invalid, or
   rejects one the spec says is valid (analyzer bug).
C. The runtime semantics differ from what the rule's natural-language
   intent would suggest (user-rule bug — for finding bugs in user
   programs, not just the compiler).

The two specs are at:
  ../f/docs/FWL_V01_SPEC.md     Language semantics (authoritative)
  ../f/docs/PKT_V01_SPEC.md     Test case format

The implementation is at ../f/fwl/fwl/. Read it. Look for thin
abstractions, recent fixes, places where parser/analyzer/interpreter/
emitter make independent decisions that could drift.

Workflow per hypothesis:
1. Form a hypothesis. State it in one sentence before testing.
2. Write a candidate .pkt to <kb>/corpus/from_hunt/<descriptive>.pkt.
3. Test: `cd ../f/fwl && .venv/bin/fwl test <kb>/corpus/from_hunt/...`
4. Inspect:
   - PASS = no bug visible. Try another hypothesis.
   - interpreter fail / bpf fail with same actual value = expected
     was wrong; this is a miss, not a bug.
   - interpreter and bpf disagree = REAL BUG.
5. Document every real bug as a finding under <kb>/findings/, every
   solid miss under <kb>/misses/. Use the format from
   ../f-hone/docs/HONE_REPO_DESIGN.md (YAML frontmatter + markdown
   body).
6. Promote real-bug .pkt cases to <kb>/corpus/from_hunt/<date>/ so
   the next regression run picks them up.

Stopping criteria:
- 3+ real bugs found, OR
- 30+ iterations with no new finding, OR
- diminishing-returns judgment.

When you stop, summarize what surfaces you covered and what classes
of bugs you ruled out. Even null findings have value — they tell us
the corpus already covers that area.

Be deliberate. Don't shotgun cases — each one should test a specific
hypothesis you can articulate. The bug HAS to be in the
implementation or the spec, not in your hypothesis.

Begin by reading recent git log of ../f, the four implementation
modules (parser/analyzer/interpreter/emitter), and a sample of
existing findings under <kb>/findings/ to avoid re-discovering known
bugs."""


@dataclass
class HuntResult:
  """Aggregate outcome of one `hone hunt` invocation."""
  total_cost_usd: float = 0.0
  turns: int = 0
  context_items: int = 0


def _format_context(prior_items: list[dict]) -> str:
  """Render Solr-pulled prior findings/misses/patterns as agent context.

  Format keeps each item compact — id, type, summary, severity,
  pattern_tags. Body is omitted; the agent can Read the file directly
  if it wants more.
  """
  if not prior_items:
    return (
      "No prior findings/misses in the knowledge base for the target's "
      "feature surface yet. You're hunting fresh ground.\n"
    )
  lines = [
    "Prior findings/misses/patterns relevant to this target. Use as "
    "context — don't re-test hypotheses already in the misses list, "
    "and look for recurrences of patterns already documented:\n"
  ]
  for item in prior_items:
    item_id = item.get("id", "?")
    item_type = item.get("type", "?")
    summary = (item.get("summary", "") or "").strip().split("\n", 1)[0]
    severity = item.get("severity", "")
    tags = item.get("pattern_tags", []) or []
    line = f"- [{item_type}] {item_id}"
    if severity:
      line += f"  severity={severity}"
    if tags:
      line += f"  patterns={','.join(tags)}"
    if summary:
      line += f"\n    {summary[:200]}"
    lines.append(line)
  return "\n".join(lines) + "\n"


def _load_focus_prompt(focus: str | None) -> str:
  """Return the named hunt-focus prompt block, or "" when none.

  Focus prompts live in `harness/agents/prompts/<focus>.md` (e.g.
  `nat-bypass`, `conntrack-poisoning`, `checksum-corruption`); they
  narrow a hunt onto one bug class by appending targeted guidance to the
  base system prompt."""
  if not focus:
    return ""
  path = Path(__file__).parent / "prompts" / f"{focus}.md"
  if not path.exists():
    raise FileNotFoundError(
      f"unknown hunt focus '{focus}' (no {path.name} in prompts/)"
    )
  return "\n\n## Hunt Focus\n\n" + path.read_text(encoding="utf-8")


async def hunt(
  kb_root: Path,
  target: Path | None = None,
  model: str = _DEFAULT_MODEL,
  max_turns: int = 80,
  fwl_repo_root: Path | None = None,
  solr_url: str | None = None,
  context_rows: int = 20,
  focus: str | None = None,
) -> HuntResult:
  """Run one hunt session, streaming Claude's turns to stdout.

  `kb_root` is where findings/misses/corpus get written.
  `target` is a .fw file (or directory of them) to focus on; if
    None, the agent picks targets from the FWL repo's examples.
  `fwl_repo_root` lets the agent discover the FWL source layout
    (defaults to ../f relative to kb_root).
  `solr_url` enables retrieval-augmented hunt: queries Solr for prior
    findings/misses keyed on the target's protocols + builtins and
    injects them into the system prompt as context. Skip when None.
  """
  kb_root = kb_root.resolve()
  cwd = (
    fwl_repo_root.resolve() if fwl_repo_root
    else (kb_root.parent / "f").resolve()
  )

  # Materialize the from_hunt subdirs so the agent doesn't trip on
  # mkdir-of-already-exists or write to the wrong place.
  (kb_root / "corpus" / "from_hunt").mkdir(parents=True, exist_ok=True)
  (kb_root / "findings").mkdir(parents=True, exist_ok=True)
  (kb_root / "misses").mkdir(parents=True, exist_ok=True)

  # Pull prior knowledge from Solr (if configured) keyed on the
  # target's surface features. Agents that see "we already tried X
  # and it was safe" don't waste turns re-proposing X.
  prior_items: list[dict] = []
  if solr_url and target is not None and target.is_file():
    try:
      from ..retrieval.indexer import query_relevant
      from ..retrieval.solr_client import SolrClient
      feats = extract_from_path(target)
      client = SolrClient(base_url=solr_url)
      if client.ping():
        prior_items = query_relevant(
          client,
          protocols=list(feats.protocols),
          builtins=list(feats.builtins),
          rows=context_rows,
        )
    except Exception as exc:  # noqa: BLE001 — retrieval is best-effort
      print(f"[warn] Solr retrieval failed, hunting blind: {exc}")

  context_block = _format_context(prior_items)
  full_system = (
    _HUNT_SYSTEM_PROMPT + _load_focus_prompt(focus)
    + "\n\n## Prior Knowledge\n\n" + context_block
  )

  # Capture the claude CLI's own stderr to a sibling log so the next
  # mid-stream subprocess crash produces a real diagnostic instead of
  # the SDK's hardcoded "Check stderr output for details" placeholder.
  stderr_log_path = (
    kb_root / "meta" / f"hunt-stderr-{int(time.time())}.log"
  )
  stderr_log_path.parent.mkdir(parents=True, exist_ok=True)
  stderr_log = open(stderr_log_path, "w", encoding="utf-8")

  options = ClaudeCodeOptions(
    system_prompt=full_system,
    model=model,
    max_turns=max_turns,
    cwd=str(cwd),
    permission_mode="bypassPermissions",
    allowed_tools=["Read", "Bash", "Write", "Edit", "Grep", "Glob"],
    settings='{"sandbox":{"enabled":false}}',
    extra_args={"debug-to-stderr": None},
    debug_stderr=stderr_log,
  )

  if target is None:
    user_prompt = (
      f"Hunt for bugs in the FWL v0.1 compiler. Knowledge base: "
      f"{kb_root}. Working dir: {cwd}. Budget: {max_turns} turns. "
      f"Begin."
    )
  else:
    user_prompt = (
      f"Hunt for bugs in this FWL program: {target.resolve()}. "
      f"Knowledge base: {kb_root}. Working dir: {cwd}. "
      f"Budget: {max_turns} turns. Begin."
    )

  result = HuntResult(context_items=len(prior_items))
  print(f"[hunt] claude CLI stderr -> {stderr_log_path}")
  try:
    async for msg in query(prompt=user_prompt, options=options):
      if isinstance(msg, AssistantMessage):
        result.turns += 1
        for block in msg.content:
          if isinstance(block, TextBlock):
            text = block.text.strip()
            if text:
              preview = text if len(text) < 800 else text[:800] + "..."
              print(f"\n[turn {result.turns}]\n{preview}\n")
      elif isinstance(msg, ResultMessage):
        if msg.total_cost_usd is not None:
          result.total_cost_usd = msg.total_cost_usd
  finally:
    stderr_log.flush()
    stderr_log.close()
    # If the file is empty, drop it so the meta dir doesn't accumulate
    # empty turds for clean runs.
    try:
      if stderr_log_path.stat().st_size == 0:
        stderr_log_path.unlink()
    except OSError:
      pass

  return result
