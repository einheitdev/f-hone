"""Subprocess plumbing around the `fwl` CLI.

Every oracle that goes through the FWL compiler shells out via this
module so the rest of the harness has one place to set the binary
path, environment, and timeout.
"""
from __future__ import annotations
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class FwlNotFound(RuntimeError):
  """Raised when the configured fwl binary isn't on the filesystem."""


@dataclass(frozen=True)
class FwlInvocation:
  """Captured stdout/stderr/exit of one `fwl` call."""
  argv: tuple[str, ...]
  exit_code: int
  stdout: str
  stderr: str

  @property
  def ok(self) -> bool:
    """True iff the process exited 0."""
    return self.exit_code == 0


def resolve_fwl_bin(explicit: str | None = None) -> str:
  """Return the path to the fwl binary, defaulting to PATH lookup.

  Priority: explicit arg > $HONE_FWL_BIN env var > shutil.which('fwl').
  """
  candidate = (
    explicit or os.environ.get("HONE_FWL_BIN") or shutil.which("fwl")
  )
  if not candidate:
    raise FwlNotFound(
      "fwl binary not found. Pass --fwl-bin, set HONE_FWL_BIN, or "
      "install fwl on PATH."
    )
  if not Path(candidate).exists():
    raise FwlNotFound(f"fwl binary not found at {candidate}")
  return candidate


def run_fwl(
  fwl_bin: str,
  *args: str,
  cwd: Path | None = None,
  timeout: float = 60.0,
) -> FwlInvocation:
  """Invoke `fwl <args>`, capturing stdout/stderr.

  Doesn't raise on non-zero exit — callers inspect `FwlInvocation.ok`
  and the exit code. Raises only on hard failures (binary missing,
  timeout exceeded).
  """
  argv = (fwl_bin, *args)
  proc = subprocess.run(
    argv,
    cwd=str(cwd) if cwd else None,
    capture_output=True,
    text=True,
    timeout=timeout,
  )
  return FwlInvocation(
    argv=argv,
    exit_code=proc.returncode,
    stdout=proc.stdout,
    stderr=proc.stderr,
  )
