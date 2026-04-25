"""Extract structural features from a target .fw program.

Used by `hone hunt` to query Solr for prior findings/misses keyed
on the same protocols and built-ins. Stays purely textual — no Lark
dependency on hone — because the agent cares about what the rule
mentions, not the parsed AST.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TargetFeatures:
  """Surface features extracted from .fw text."""
  protocols: set[str] = field(default_factory=set)
  builtins: set[str] = field(default_factory=set)
  fields: set[str] = field(default_factory=set)
  has_rate_limit: bool = False
  rule_count: int = 0
  has_default: bool = False


_PROTO_RE = re.compile(r"\bpkt\.proto\s*==\s*(tcp|udp|icmp)\b")
_FIELD_RE = re.compile(
  r"\bpkt\.(proto|src_ip|dst_ip|src_port|dst_port|tcp\.syn|tcp\.ack)\b"
)
_BUILTIN_RE = re.compile(r"\b(rate_limit)\s*\(")
_RULE_RE = re.compile(r"^\s*(allow|drop|log|count)\b", re.MULTILINE)
_DEFAULT_RE = re.compile(r"^\s*default\b", re.MULTILINE)


def extract(source: str) -> TargetFeatures:
  """Pull surface features out of a .fw program's text."""
  feats = TargetFeatures()
  for m in _PROTO_RE.finditer(source):
    feats.protocols.add(m.group(1))
  for m in _FIELD_RE.finditer(source):
    feats.fields.add("pkt." + m.group(1))
  for m in _BUILTIN_RE.finditer(source):
    name = m.group(1)
    feats.builtins.add(name)
    if name == "rate_limit":
      feats.has_rate_limit = True
  feats.rule_count = len(_RULE_RE.findall(source))
  feats.has_default = bool(_DEFAULT_RE.search(source))
  # If pkt.tcp.* is referenced but pkt.proto == tcp isn't (e.g.,
  # access happens inside an OR branch), still mark tcp as protocol.
  if any(f.startswith("pkt.tcp") for f in feats.fields):
    feats.protocols.add("tcp")
  return feats


def extract_from_path(path: Path) -> TargetFeatures:
  """Read a .fw file from disk and extract its features."""
  return extract(path.read_text(encoding="utf-8"))
