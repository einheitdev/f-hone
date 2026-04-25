"""Self-critique pass.

After a `hone hunt` round (or once a knowledge base has accumulated
findings + misses), Claude reads the recent activity and writes a
meta-report that the human can act on:

  - Which strategies/hypotheses are paying off?
  - Which hypotheses keep missing — i.e. where is the harness
    convinced something is broken when it isn't?
  - What surfaces remain uncovered (no findings + no misses)?
  - Concrete suggestions: new strategies, new prompts, new corpus
    entries.

Output goes to <kb>/meta/<YYYY-MM-DD>-critique.md so it accumulates
over time and we can diff successive critiques.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import date
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


_SYSTEM_PROMPT = """You are reviewing a security harness's own
performance. The harness hunts bugs in the FWL compiler/runtime; the
knowledge base under <kb>/ holds its findings, misses, and patterns.

Your job: produce a short, blunt critique that helps the human
operating the harness decide what to tune next.

Read:
  - <kb>/findings/*.md     confirmed bugs
  - <kb>/misses/*.md       hypotheses that turned out to be wrong
  - <kb>/patterns/*.md     abstracted bug classes
  - <kb>/meta/*.md         prior critiques (if any)

Then write ONE markdown file at <kb>/meta/<YYYY-MM-DD>-critique.md.
Use the date passed to you in the user prompt — do NOT use `date`
shell command. Format:

```
---
type: critique
created: <date>
---

# Self-critique <date>

## What's working
- ...

## What's missing
- ...

## Coverage gaps
- ...

## Recommendations
- ...
```

Quality bar:
- "What's working" must cite specific finding ids or pattern ids.
- "What's missing" must point at concrete surfaces of FWL
  (parser/analyzer/interpreter/emitter, specific protocols,
  built-ins) the harness hasn't probed.
- Recommendations must be ACTIONABLE — "add a strategy that does X",
  not "improve coverage". Name the strategy, the protocol, or the
  prompt change.
- If the kb is too small to critique meaningfully, say so and stop.

Be blunt. If most findings cluster in one area while another area is
untouched, say that. The point of this pass is to surface honest
weaknesses, not to congratulate the harness."""


@dataclass
class CritiqueResult:
  """Outcome of one `hone critique` invocation."""
  total_cost_usd: float = 0.0
  turns: int = 0
  report_path: Path | None = None


def _summarize_kb(kb_root: Path) -> str:
  """Compact catalog the agent reads to plan its critique."""
  findings, misses, patterns = scan_knowledge_base(kb_root)
  lines: list[str] = []
  lines.append(
    f"Knowledge base summary: "
    f"{len(findings)} findings, {len(misses)} misses, "
    f"{len(patterns)} patterns."
  )
  if findings:
    lines.append("\nFindings:")
    for f in findings:
      summary = (f.summary or "").strip().split("\n", 1)[0][:160]
      lines.append(
        f"- {f.id}  [{f.severity.value}/{f.layer.value}]  "
        f"protocols=[{','.join(f.protocols)}]  "
        f"tags=[{','.join(f.pattern_tags)}]\n    {summary}"
      )
  if misses:
    lines.append("\nMisses:")
    for m in misses:
      hyp = (m.hypothesis or "").strip().split("\n", 1)[0][:160]
      lines.append(
        f"- {m.id}  protocols=[{','.join(m.protocols)}]  "
        f"tags=[{','.join(m.pattern_tags)}]\n    {hyp}"
      )
  if patterns:
    lines.append("\nPatterns:")
    for p in patterns:
      desc = (p.description or "").strip().split("\n", 1)[0][:160]
      n = len(p.known_instances or [])
      lines.append(f"- {p.id}  N={n}  {desc}")
  return "\n".join(lines)


async def self_critique(
  kb_root: Path,
  model: str = _DEFAULT_MODEL,
  max_turns: int = 30,
) -> CritiqueResult:
  """Run one critique pass; return cost + path of the meta report."""
  kb_root = kb_root.resolve()
  meta_dir = kb_root / "meta"
  meta_dir.mkdir(parents=True, exist_ok=True)

  findings, misses, patterns = scan_knowledge_base(kb_root)
  if not findings and not misses:
    print(
      "Knowledge base has no findings or misses yet — nothing to "
      "critique. Run `hone fuzz` or `hone hunt` first."
    )
    return CritiqueResult()

  today = date.today().isoformat()
  expected_path = meta_dir / f"{today}-critique.md"
  catalog = _summarize_kb(kb_root)

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
Today's date: {today}. Use this date in the report filename and
frontmatter.

{catalog}

Read each finding/miss body for context, then write the critique
to {expected_path.relative_to(kb_root)}."""

  result = CritiqueResult()
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

  if expected_path.exists():
    result.report_path = expected_path
  else:
    matches = sorted(meta_dir.glob(f"{today}*.md"))
    if matches:
      result.report_path = matches[-1]
  return result
