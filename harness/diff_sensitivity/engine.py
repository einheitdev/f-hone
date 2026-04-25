"""Map a git diff against the FWL repo onto FWL constructs.

The construct map is hand-maintained in
`f-hone/config/compiler_construct_map.yaml`. Each entry says
"changes under this path file touch these FWL constructs". When the
compiler grows new files, the map is updated by hand.
"""
from __future__ import annotations
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import yaml


# Constants exported for tests / display.
WILDCARD = "all"


@dataclass
class ConstructImpact:
  """Outcome of mapping a diff to constructs."""
  changed_files: list[str] = field(default_factory=list)
  impacted_constructs: set[str] = field(default_factory=set)
  unmapped_files: list[str] = field(default_factory=list)
  base_ref: str = ""
  head_ref: str = "HEAD"


def load_construct_map(path: Path) -> dict[str, list[str]]:
  """Read the static path → constructs map. Empty if the file
  doesn't exist (a freshly-cloned repo without the config)."""
  if not path.is_file():
    return {}
  data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
  if not isinstance(data, dict):
    raise ValueError(
      f"construct map at {path} must be a YAML mapping"
    )
  out: dict[str, list[str]] = {}
  for k, v in data.items():
    if isinstance(v, list):
      out[str(k)] = [str(x) for x in v]
    elif isinstance(v, str):
      out[str(k)] = [v]
    else:
      raise ValueError(
        f"construct map entry {k!r} must be a string or list"
      )
  return out


def _git_diff_files(repo: Path, base: str, head: str) -> list[str]:
  """`git diff --name-only base..head` from inside `repo`."""
  if shutil.which("git") is None:
    raise RuntimeError("git not found on PATH")
  cmd = ["git", "-C", str(repo), "diff", "--name-only", f"{base}..{head}"]
  out = subprocess.run(
    cmd, capture_output=True, text=True, check=True,
  )
  return [
    line.strip() for line in out.stdout.splitlines() if line.strip()
  ]


def diff_impact(
  repo: Path,
  base: str,
  head: str = "HEAD",
  construct_map_path: Path | None = None,
  changed_files: list[str] | None = None,
) -> ConstructImpact:
  """Run `git diff base..head` against `repo`, map each changed file
  to FWL constructs, return a ConstructImpact summary.

  `changed_files` lets callers (and tests) bypass the git invocation
  by supplying the diff contents directly.
  """
  files = changed_files if changed_files is not None else _git_diff_files(
    repo, base, head,
  )
  cmap_path = construct_map_path or (
    Path(__file__).resolve().parents[2]
    / "config" / "compiler_construct_map.yaml"
  )
  cmap = load_construct_map(cmap_path)
  impact = ConstructImpact(
    changed_files=list(files),
    base_ref=base,
    head_ref=head,
  )
  for f in files:
    matched = False
    for prefix, constructs in cmap.items():
      if f == prefix or f.startswith(prefix.rstrip("/") + "/") or (
        prefix.endswith("/") and f.startswith(prefix)
      ):
        for c in constructs:
          if c == WILDCARD:
            impact.impacted_constructs.add(WILDCARD)
          else:
            impact.impacted_constructs.add(c)
        matched = True
    if not matched:
      impact.unmapped_files.append(f)
  return impact
