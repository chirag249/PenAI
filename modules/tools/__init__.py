# modules/tools/__init__.py
"""
Lightweight package bootstrap for modules.tools.

Do NOT import concrete parser modules here (they may be missing).
Expose a single safe dispatcher from the parsers subpackage so imports
like `from modules.tools.parsers import parse_tool_envelope` work.
"""
from importlib import import_module
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

# Lazy import helper for the parsers package
def _ensure_parsers_pkg():
    try:
        mod = import_module("modules.tools.parsers")
        return mod
    except Exception as e:
        logger.debug("modules.tools.parsers import failed: %s", e)
        raise

# Re-export the central parse_tool_envelope if available
try:
    parsers = _ensure_parsers_pkg()
    parse_tool_envelope = getattr(parsers, "parse_tool_envelope")
except Exception:
    # Provide a fallback so other modules can still import the package,
    # but raising an informative error only when parse_tool_envelope is used.
    def parse_tool_envelope(tool_name, envelope, run_dir):
        raise RuntimeError(
            "modules.tools.parsers.parse_tool_envelope is not available. "
            "Ensure modules/tools/parsers/__init__.py exists and defines parse_tool_envelope."
        )
