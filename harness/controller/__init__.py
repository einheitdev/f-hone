"""Long-running harness controller.

Watches `.fw` files for changes, schedules agent pods across discovery
strategies, manages per-pod budget, and aggregates findings.

Not yet implemented — `scheduler.py`, `dispatcher.py`, `watcher.py` are
stubs. The `hone hunt` and `hone fuzz` commands route through here once
agents land.
"""
