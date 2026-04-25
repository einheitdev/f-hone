"""LLM-backed agent pods.

Each pod runs the hypothesis -> packet -> execute -> classify loop
described in F_SECURITY_HARNESS.md. Pods authenticate through
claude-code-sdk so LLM cost goes against the user's Claude Code
subscription rather than a separate API key.

Not yet implemented.
"""
