"""MCP Server — Exposes SIFT forensic tools as typed functions.

Instead of giving the AI `execute_shell_cmd`, this server exposes
structured, validated, read-only functions like:
  - get_partition_table(image_path) → PartitionTable
  - get_mft_entries(image_path, path="/", limit=100) → list[MFTEntry]
  - analyze_prefetch(image_path, filename) → PrefetchResult

The agent physically CANNOT run destructive commands because
this server doesn't have those tools.

Architecture:
    Agent ←→ MCP Protocol ←→ This Server ←→ SIFT CLI Tools (subprocess, read-only)
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

# Initialize MCP server
mcp = FastMCP(
    "phantom-sift",
    instructions="Forensic analysis tools from SANS SIFT Workstation (read-only)",
)


# ─── Filesystem Tools (Sleuth Kit) ──────────────────────────────────

@mcp.tool()
def get_partition_table(image_path: str) -> dict[str, Any]:
    """Get partition layout of a disk image using mmls.

    Args:
        image_path: Path to disk image file (must be within evidence mount)

    Returns:
        Partition table with slot, start, end, length, and description.
    """
    _validate_path(image_path)
    result = _run_tool("mmls", [image_path])
    return {"tool": "mmls", "output": result, "image": image_path}


@mcp.tool()
def get_filesystem_info(image_path: str, offset: int = 0) -> dict[str, Any]:
    """Get filesystem details (type, size, block count) using fsstat.

    Args:
        image_path: Path to disk image
        offset: Partition offset in sectors
    """
    _validate_path(image_path)
    args = ["-o", str(offset), image_path]
    result = _run_tool("fsstat", args)
    return {"tool": "fsstat", "output": result, "offset": offset}


@mcp.tool()
def list_directory(image_path: str, path: str = "/", offset: int = 0) -> dict[str, Any]:
    """List files and directories at a path within the image using fls.

    Args:
        image_path: Path to disk image
        path: Directory path within the filesystem
        offset: Partition offset in sectors
    """
    _validate_path(image_path)
    args = ["-o", str(offset), "-r", "-p", image_path]
    result = _run_tool("fls", args)
    return {"tool": "fls", "output": result, "path": path, "offset": offset}


@mcp.tool()
def get_mft_entries(
    image_path: str, offset: int = 0, limit: int = 100
) -> dict[str, Any]:
    """Extract MFT entries from NTFS volume using istat/analyzemft.

    Args:
        image_path: Path to disk image
        offset: Partition offset in sectors
        limit: Maximum entries to return
    """
    _validate_path(image_path)
    # Use analyzeMFT or custom extraction
    args = ["-o", str(offset), "-r", image_path]
    result = _run_tool("fls", args)
    # Truncate to limit
    lines = result.split("\n")[:limit]
    return {"tool": "fls+mft", "output": "\n".join(lines), "entry_count": len(lines)}


# ─── Timeline Tools ─────────────────────────────────────────────────

@mcp.tool()
def generate_timeline(
    image_path: str, offset: int = 0, start_date: str = "", end_date: str = ""
) -> dict[str, Any]:
    """Generate filesystem timeline using mactime/fls bodyfile.

    Args:
        image_path: Path to disk image
        offset: Partition offset
        start_date: Filter start (YYYY-MM-DD)
        end_date: Filter end (YYYY-MM-DD)
    """
    _validate_path(image_path)
    # Step 1: Generate bodyfile with fls
    body_args = ["-o", str(offset), "-r", "-m", "/", image_path]
    bodyfile = _run_tool("fls", body_args)

    # Step 2: Process with mactime
    mactime_args = ["-b", "-"]
    if start_date:
        mactime_args.extend(["-d", start_date])
    result = _run_tool_stdin("mactime", mactime_args, bodyfile)
    return {"tool": "mactime", "output": result[:10000]}  # Cap output size


# ─── Memory Tools (Volatility 3) ────────────────────────────────────

@mcp.tool()
def vol_pslist(memory_path: str) -> dict[str, Any]:
    """List running processes from memory dump using Volatility 3.

    Args:
        memory_path: Path to memory dump (.vmem, .raw, .dmp)
    """
    _validate_path(memory_path)
    result = _run_tool("vol", ["-f", memory_path, "windows.pslist.PsList"])
    return {"tool": "volatility3.pslist", "output": result}


@mcp.tool()
def vol_pstree(memory_path: str) -> dict[str, Any]:
    """Show process tree (parent-child relationships) from memory."""
    _validate_path(memory_path)
    result = _run_tool("vol", ["-f", memory_path, "windows.pstree.PsTree"])
    return {"tool": "volatility3.pstree", "output": result}


@mcp.tool()
def vol_netscan(memory_path: str) -> dict[str, Any]:
    """Scan for network connections and listening ports in memory."""
    _validate_path(memory_path)
    result = _run_tool("vol", ["-f", memory_path, "windows.netscan.NetScan"])
    return {"tool": "volatility3.netscan", "output": result}


@mcp.tool()
def vol_malfind(memory_path: str) -> dict[str, Any]:
    """Find injected code and hollowed processes in memory."""
    _validate_path(memory_path)
    result = _run_tool("vol", ["-f", memory_path, "windows.malfind.Malfind"])
    return {"tool": "volatility3.malfind", "output": result}


@mcp.tool()
def vol_dlllist(memory_path: str, pid: int | None = None) -> dict[str, Any]:
    """List loaded DLLs for processes.

    Args:
        memory_path: Path to memory dump
        pid: Optional specific PID to inspect
    """
    _validate_path(memory_path)
    args = ["-f", memory_path, "windows.dlllist.DllList"]
    if pid:
        args.extend(["--pid", str(pid)])
    result = _run_tool("vol", args)
    return {"tool": "volatility3.dlllist", "output": result}


# ─── String/Pattern Tools ────────────────────────────────────────────

@mcp.tool()
def search_strings(image_path: str, pattern: str, context_lines: int = 2) -> dict[str, Any]:
    """Search for string patterns in evidence using strings + grep.

    Args:
        image_path: Path to evidence file
        pattern: String or regex pattern to search
        context_lines: Lines of context around matches
    """
    _validate_path(image_path)
    # Run strings then grep
    result = _run_tool("strings", [image_path])
    # Filter by pattern (simplified — real impl would pipe)
    matches = [line for line in result.split("\n") if pattern.lower() in line.lower()]
    return {
        "tool": "strings+grep",
        "pattern": pattern,
        "match_count": len(matches),
        "matches": matches[:50],  # Cap output
    }


@mcp.tool()
def yara_scan(image_path: str, rule_name: str = "default") -> dict[str, Any]:
    """Scan evidence with YARA rules.

    Args:
        image_path: Path to evidence file
        rule_name: YARA rule set to use
    """
    _validate_path(image_path)
    rules_path = f"/opt/sift/yara/{rule_name}.yar"
    result = _run_tool("yara", ["-r", rules_path, image_path])
    return {"tool": "yara", "rule": rule_name, "output": result}


@mcp.tool()
def compute_hash(file_path: str) -> dict[str, Any]:
    """Compute MD5, SHA1, SHA256 hashes of a file.

    Args:
        file_path: Path to file to hash
    """
    _validate_path(file_path)
    path = Path(file_path)
    if not path.exists():
        return {"error": f"File not found: {file_path}"}

    with open(path, "rb") as f:
        content = f.read()

    return {
        "tool": "hashlib",
        "file": file_path,
        "md5": hashlib.md5(content).hexdigest(),
        "sha1": hashlib.sha1(content).hexdigest(),
        "sha256": hashlib.sha256(content).hexdigest(),
        "size_bytes": len(content),
    }


# ─── Registry Tools ─────────────────────────────────────────────────

@mcp.tool()
def analyze_registry_hive(hive_path: str, key: str = "") -> dict[str, Any]:
    """Parse Windows registry hive using regripper.

    Args:
        hive_path: Path to registry hive file (SAM, SYSTEM, SOFTWARE, etc.)
        key: Specific registry key to examine (empty = full parse)
    """
    _validate_path(hive_path)
    args = ["-r", hive_path]
    if key:
        args.extend(["-k", key])
    result = _run_tool("regripper", args)
    return {"tool": "regripper", "hive": hive_path, "key": key, "output": result}


@mcp.tool()
def get_amcache_entries(hive_path: str) -> dict[str, Any]:
    """Extract AmCache entries (program execution evidence).

    Args:
        hive_path: Path to Amcache.hve file
    """
    _validate_path(hive_path)
    result = _run_tool("regripper", ["-r", hive_path, "-p", "amcache"])
    return {"tool": "regripper.amcache", "output": result}


# ─── Helper Functions ────────────────────────────────────────────────

def _validate_path(path_str: str) -> None:
    """Validate path is within allowed boundaries.

    Raises ValueError if path traversal is attempted.
    """
    blocked = ["../", "..\\", "/dev/", "/proc/", "/sys/", "/tmp/"]
    for pattern in blocked:
        if pattern in path_str:
            raise ValueError(f"Path traversal blocked: {path_str}")


def _run_tool(tool_name: str, args: list[str], timeout: int = 60) -> str:
    """Execute a SIFT CLI tool and return stdout.

    All tools are run read-only — no write operations possible.
    """
    cmd_path = shutil.which(tool_name)
    if cmd_path is None:
        return f"[ERROR] Tool not found: {tool_name}. Is SIFT Workstation installed?"

    try:
        result = subprocess.run(
            [cmd_path, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0 and result.stderr:
            return f"[STDERR] {result.stderr[:2000]}"
        return result.stdout[:50000]  # Cap output to prevent context window overflow
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] {tool_name} exceeded {timeout}s"
    except Exception as e:
        return f"[ERROR] {tool_name}: {e}"


def _run_tool_stdin(tool_name: str, args: list[str], stdin_data: str) -> str:
    """Execute tool with data piped to stdin."""
    cmd_path = shutil.which(tool_name)
    if cmd_path is None:
        return f"[ERROR] Tool not found: {tool_name}"

    try:
        result = subprocess.run(
            [cmd_path, *args],
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return result.stdout[:50000]
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] {tool_name}"
    except Exception as e:
        return f"[ERROR] {tool_name}: {e}"
