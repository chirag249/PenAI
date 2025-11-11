# modules/tools/adapter_base.py
from __future__ import annotations
from typing import Dict, Any

class ToolAdapter:
    """
    Base class for a tool adapter.

    Implementations should provide:
      - name: str
      - run(outdir: str, target: str | None = None) -> Dict[str, Any]
    Return value should include stdout/stderr/status and optional structured output.
    """
    name = "base"

    def run(self, outdir: str, target: str | None = None) -> Dict[str, Any]:
        raise NotImplementedError("Adapters must implement run()")
