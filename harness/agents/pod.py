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
from dataclasses import dataclass
from pathlib import Path

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


async def hunt(
  kb_root: Path,
  target: Path | None = None,
  model: str = _DEFAULT_MODEL,
  max_turns: int = 80,
  fwl_repo_root: Path | None = None,
) -> HuntResult:
  """Run one hunt session, streaming Claude's turns to stdout.

  `kb_root` is where findings/misses/corpus get written.
  `target` is a .fw file (or directory of them) to focus on; if
    None, the agent picks targets from the FWL repo's examples.
  `fwl_repo_root` lets the agent discover the FWL source layout
    (defaults to ../f relative to kb_root).
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

  options = ClaudeCodeOptions(
    system_prompt=_HUNT_SYSTEM_PROMPT,
    model=model,
    max_turns=max_turns,
    cwd=str(cwd),
    permission_mode="bypassPermissions",
    allowed_tools=["Read", "Bash", "Write", "Edit", "Grep", "Glob"],
    settings='{"sandbox":{"enabled":false}}',
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

  result = HuntResult()
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

  return result
