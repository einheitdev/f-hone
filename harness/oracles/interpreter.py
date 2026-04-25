"""AST interpreter oracle.

Calls `fwl interpret <fw_file> <pkt_file>` and parses the output.
The interpreter prints a single line: `XDP_PASS (<rule_idx>: <action>)`
or `XDP_DROP (default: <action>)`.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path

from .fwl_subprocess import FwlInvocation, run_fwl


@dataclass(frozen=True)
class InterpreterResult:
  """One run of the AST interpreter against a (program, packet) pair."""
  action: str | None  # "XDP_PASS" | "XDP_DROP" | None on error
  rule_label: str | None  # e.g. "rule 0: drop", "default: allow"
  invocation: FwlInvocation


_LINE_RE = re.compile(
  r"^(?P<action>XDP_PASS|XDP_DROP)\s*\((?P<label>[^)]*)\)\s*$",
)


def interpret(
  fwl_bin: str,
  fw_file: Path,
  pkt_file: Path,
  timeout: float = 30.0,
) -> InterpreterResult:
  """Run the AST interpreter and return a structured outcome.

  On a clean run we get one line of stdout matching `_LINE_RE`. On
  compile failure the process exits non-zero and stderr carries the
  FwlException; we surface that via InterpreterResult.action=None.
  """
  inv = run_fwl(
    fwl_bin, "interpret", str(fw_file), str(pkt_file), timeout=timeout
  )
  if not inv.ok:
    return InterpreterResult(
      action=None, rule_label=None, invocation=inv
    )
  for line in inv.stdout.splitlines():
    line = line.strip()
    match = _LINE_RE.match(line)
    if match:
      return InterpreterResult(
        action=match.group("action"),
        rule_label=match.group("label").strip(),
        invocation=inv,
      )
  return InterpreterResult(action=None, rule_label=None, invocation=inv)
