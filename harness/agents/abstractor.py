"""Pattern abstraction pass.

Periodically (after N+ findings accumulate) Claude reads every
finding and proposes pattern abstractions — the bug *class* the
individual instances cluster into. Output is a markdown file under
<kb>/patterns/ that a human reviews + merges.

Per F_SECURITY_HARNESS.md:
  > The harness should periodically abstract from findings to
  > patterns. After N findings accumulate, run a specific LLM pass
  > that reads all findings and proposes pattern abstractions. The
  > output is a draft patterns/*.md file. A human reviews it, edits
  > if needed, and merges.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path

from claude_code_sdk import (
  AssistantMessage,
  ClaudeCodeOptions,
  ResultMessage,
  TextBlock,
  query,
)

from ..knowledge.reader import scan_knowledge_base


_DEFAULT_MODEL = "claude-opus-4-7"


_SYSTEM_PROMPT = """You are abstracting patterns from a knowledge
base of confirmed FWL compiler/runtime bugs.

Your job:
1. Read the findings in <kb>/findings/ (you have Read access).
2. Group them into recurring bug classes — patterns. Two findings
   that share a root cause shape (e.g., "claimed-vs-actual length",
   "missing bounds check on optional header", "off-by-one at u32
   boundary") belong in the same pattern.
3. For each pattern with N >= 2 instances, propose a pattern document
   under <kb>/patterns/<slug>.md using the format from
   docs/HONE_REPO_DESIGN.md (YAML frontmatter + markdown body with
   Description, Check Strategy, Known Instances, Where to Look Next).
4. For pattern instances of N >= 5, the pattern doc is high-confidence;
   for N = 2-4 it's a hypothesis the human should evaluate.

Quality bar:
- A pattern must point FORWARD — "where to look next" should name
  specific code or protocol surfaces the harness hasn't covered yet.
- Don't invent patterns from a single finding (no abstraction
  without repetition).
- If the findings are too few or too varied to cluster, say so —
  output "no patterns yet" and stop.

When you're done, summarize: how many patterns proposed, how many
findings each covers, what surfaces remain uncovered."""


@dataclass
class AbstractResult:
  """Outcome of one `hone abstract` invocation."""
  total_cost_usd: float = 0.0
  turns: int = 0
  patterns_written: list[Path] = None  # type: ignore[assignment]

  def __post_init__(self):
    if self.patterns_written is None:
      self.patterns_written = []


def _list_findings_summary(kb_root: Path) -> str:
  """One-line-per-finding catalog the agent reads to plan its grouping."""
  findings, _, _ = scan_knowledge_base(kb_root)
  if not findings:
    return "No findings present in the knowledge base."
  lines = [f"{len(findings)} findings present:"]
  for f in findings:
    summary = (f.summary or "").strip().split("\n", 1)[0][:160]
    lines.append(
      f"- {f.id}  [{f.severity.value}/{f.layer.value}]  "
      f"tags=[{','.join(f.pattern_tags)}]\n    {summary}"
    )
  return "\n".join(lines)


async def abstract_patterns(
  kb_root: Path,
  model: str = _DEFAULT_MODEL,
  max_turns: int = 30,
  min_findings: int = 5,
) -> AbstractResult:
  """Run the pattern-abstraction pass.

  Returns AbstractResult with cost + paths to any new pattern docs.
  """
  kb_root = kb_root.resolve()
  catalog = _list_findings_summary(kb_root)
  findings, _, patterns = scan_knowledge_base(kb_root)

  if len(findings) < min_findings:
    print(
      f"Only {len(findings)} findings present (need >= {min_findings}). "
      f"Pattern abstraction skipped."
    )
    return AbstractResult()

  patterns_dir = kb_root / "patterns"
  patterns_before = set(p.name for p in patterns_dir.glob("*.md"))

  options = ClaudeCodeOptions(
    system_prompt=_SYSTEM_PROMPT,
    model=model,
    max_turns=max_turns,
    cwd=str(kb_root),
    permission_mode="bypassPermissions",
    allowed_tools=["Read", "Write", "Glob", "Grep"],
    settings='{"sandbox":{"enabled":false}}',
  )

  user_prompt = f"""Knowledge base: {kb_root}.
Existing patterns: {len(patterns)}.
{catalog}

Read each finding's body to understand the root cause. Propose
patterns where N >= 2 findings share a root-cause shape."""

  result = AbstractResult()
  async for msg in query(prompt=user_prompt, options=options):
    if isinstance(msg, AssistantMessage):
      result.turns += 1
      for block in msg.content:
        if isinstance(block, TextBlock):
          text = block.text.strip()
          if text:
            preview = text if len(text) < 600 else text[:600] + "..."
            print(f"\n[turn {result.turns}]\n{preview}\n")
    elif isinstance(msg, ResultMessage):
      if msg.total_cost_usd is not None:
        result.total_cost_usd = msg.total_cost_usd

  patterns_after = set(p.name for p in patterns_dir.glob("*.md"))
  for new in sorted(patterns_after - patterns_before):
    result.patterns_written.append(patterns_dir / new)
  return result


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(text: str) -> str:
  """Filesystem-safe slug helper for pattern ids."""
  return _SLUG_RE.sub("-", text.lower()).strip("-")[:80]
