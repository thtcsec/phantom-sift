"""SIFT tool wrappers — availability checking."""

from __future__ import annotations

import shutil
from typing import Any

# All SIFT tools we wrap via MCP
REQUIRED_TOOLS = [
    "mmls",         # Partition table (Sleuth Kit)
    "fsstat",       # Filesystem stats (Sleuth Kit)
    "fls",          # File listing (Sleuth Kit)
    "icat",         # File extraction (Sleuth Kit)
    "mactime",      # Timeline (Sleuth Kit)
    "vol",          # Volatility 3
    "strings",      # GNU strings
    "yara",         # YARA scanner
    "regripper",    # Registry parser
]

OPTIONAL_TOOLS = [
    "log2timeline.py",  # Plaso timeline
    "tshark",           # Network analysis
    "zeek",             # Network analysis
    "bulk_extractor",   # Bulk extraction
    "foremost",         # File carving
    "exiftool",         # Metadata
]


def check_tool_availability() -> dict[str, Any]:
    """Check which SIFT tools are available on the system.

    Used by `phantom-sift doctor` to validate environment.
    """
    available = []
    missing = []
    all_tools = REQUIRED_TOOLS + OPTIONAL_TOOLS

    for tool in all_tools:
        if shutil.which(tool):
            available.append(tool)
        else:
            missing.append(tool)

    return {
        "available": available,
        "missing": missing,
        "available_count": len(available),
        "total": len(all_tools),
        "required_missing": [t for t in REQUIRED_TOOLS if t in missing],
    }
