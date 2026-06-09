"""Tool Dispatcher — Bridges agent tool_use calls to MCP server functions.

When Claude responds with a tool_use block, this module:
1. Validates the call via PolicyEngine
2. Dispatches to the correct MCP tool function
3. Captures output + timing
4. Logs everything to ExecutionLogger
5. Returns structured result back to agent

This is the architectural enforcement point — the agent cannot
call tools that don't exist here.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any, Callable

import structlog

from ..core.audit_logger import ExecutionLogger
from ..core.policy import PolicyEngine
from ..mcp_server import server as mcp_module

logger = structlog.get_logger()


# Map of tool names the agent can call → actual functions
# This is the ONLY way tools get executed. If it's not here, it doesn't exist.
TOOL_REGISTRY: dict[str, Callable[..., dict[str, Any]]] = {
    # Filesystem (Sleuth Kit)
    "get_partition_table": mcp_module.get_partition_table,
    "get_filesystem_info": mcp_module.get_filesystem_info,
    "list_directory": mcp_module.list_directory,
    "get_mft_entries": mcp_module.get_mft_entries,
    # Timeline
    "generate_timeline": mcp_module.generate_timeline,
    # Memory (Volatility 3)
    "vol_pslist": mcp_module.vol_pslist,
    "vol_pstree": mcp_module.vol_pstree,
    "vol_netscan": mcp_module.vol_netscan,
    "vol_malfind": mcp_module.vol_malfind,
    "vol_dlllist": mcp_module.vol_dlllist,
    # Strings / Patterns
    "search_strings": mcp_module.search_strings,
    "yara_scan": mcp_module.yara_scan,
    "compute_hash": mcp_module.compute_hash,
    # Registry
    "analyze_registry_hive": mcp_module.analyze_registry_hive,
    "get_amcache_entries": mcp_module.get_amcache_entries,
}


def get_anthropic_tool_definitions() -> list[dict[str, Any]]:
    """Generate Anthropic-format tool definitions for all available tools.

    These are sent to Claude so it knows what tools it can call.
    """
    return [
        {
            "name": "get_partition_table",
            "description": "Get partition layout of a disk image using mmls. Returns partition table with slot, start, end, length, description.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "image_path": {"type": "string", "description": "Path to disk image file"}
                },
                "required": ["image_path"],
            },
        },
        {
            "name": "get_filesystem_info",
            "description": "Get filesystem details (type, size, block count) using fsstat.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "image_path": {"type": "string", "description": "Path to disk image"},
                    "offset": {"type": "integer", "description": "Partition offset in sectors", "default": 0},
                },
                "required": ["image_path"],
            },
        },
        {
            "name": "list_directory",
            "description": "List files and directories at a path within the image using fls. Returns file listing with metadata.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "image_path": {"type": "string", "description": "Path to disk image"},
                    "path": {"type": "string", "description": "Directory path within filesystem", "default": "/"},
                    "offset": {"type": "integer", "description": "Partition offset in sectors", "default": 0},
                },
                "required": ["image_path"],
            },
        },
        {
            "name": "get_mft_entries",
            "description": "Extract MFT entries from NTFS volume. Shows file metadata, timestamps, and allocation status.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "image_path": {"type": "string", "description": "Path to disk image"},
                    "offset": {"type": "integer", "description": "Partition offset", "default": 0},
                    "limit": {"type": "integer", "description": "Max entries to return", "default": 100},
                },
                "required": ["image_path"],
            },
        },
        {
            "name": "generate_timeline",
            "description": "Generate filesystem timeline using mactime. Shows file creation/modification/access times in chronological order.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "image_path": {"type": "string", "description": "Path to disk image"},
                    "offset": {"type": "integer", "description": "Partition offset", "default": 0},
                    "start_date": {"type": "string", "description": "Filter start date YYYY-MM-DD", "default": ""},
                    "end_date": {"type": "string", "description": "Filter end date YYYY-MM-DD", "default": ""},
                },
                "required": ["image_path"],
            },
        },
        {
            "name": "vol_pslist",
            "description": "List running processes from memory dump using Volatility 3. Shows PID, PPID, name, creation time.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "memory_path": {"type": "string", "description": "Path to memory dump (.vmem, .raw, .dmp)"}
                },
                "required": ["memory_path"],
            },
        },
        {
            "name": "vol_pstree",
            "description": "Show process tree (parent-child relationships) from memory. Reveals process injection and unusual parentage.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "memory_path": {"type": "string", "description": "Path to memory dump"}
                },
                "required": ["memory_path"],
            },
        },
        {
            "name": "vol_netscan",
            "description": "Scan for network connections and listening ports in memory. Shows local/remote IP:port and owning process.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "memory_path": {"type": "string", "description": "Path to memory dump"}
                },
                "required": ["memory_path"],
            },
        },
        {
            "name": "vol_malfind",
            "description": "Find injected code and hollowed processes in memory. Detects code injection techniques.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "memory_path": {"type": "string", "description": "Path to memory dump"}
                },
                "required": ["memory_path"],
            },
        },
        {
            "name": "vol_dlllist",
            "description": "List loaded DLLs for all or specific process. Shows DLL paths and load addresses.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "memory_path": {"type": "string", "description": "Path to memory dump"},
                    "pid": {"type": "integer", "description": "Specific PID to inspect (optional)"},
                },
                "required": ["memory_path"],
            },
        },
        {
            "name": "search_strings",
            "description": "Search for string patterns in evidence. Finds URLs, IPs, file paths, commands embedded in evidence.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "image_path": {"type": "string", "description": "Path to evidence file"},
                    "pattern": {"type": "string", "description": "String pattern to search for"},
                },
                "required": ["image_path", "pattern"],
            },
        },
        {
            "name": "yara_scan",
            "description": "Scan evidence with YARA rules for known malware signatures.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "image_path": {"type": "string", "description": "Path to evidence file"},
                    "rule_name": {"type": "string", "description": "YARA rule set name", "default": "default"},
                },
                "required": ["image_path"],
            },
        },
        {
            "name": "compute_hash",
            "description": "Compute MD5, SHA1, SHA256 hashes of a file. Use to identify known malware via threat intel.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to file to hash"}
                },
                "required": ["file_path"],
            },
        },
        {
            "name": "analyze_registry_hive",
            "description": "Parse Windows registry hive. Extracts persistence mechanisms, user activity, system config.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "hive_path": {"type": "string", "description": "Path to registry hive (SAM, SYSTEM, SOFTWARE, etc.)"},
                    "key": {"type": "string", "description": "Specific registry key to examine", "default": ""},
                },
                "required": ["hive_path"],
            },
        },
        {
            "name": "get_amcache_entries",
            "description": "Extract AmCache entries showing program execution history with timestamps and hashes.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "hive_path": {"type": "string", "description": "Path to Amcache.hve file"}
                },
                "required": ["hive_path"],
            },
        },
    ]


class ToolDispatcher:
    """Executes tool calls from the agent with policy enforcement + logging."""

    def __init__(self, policy: PolicyEngine, execution_logger: ExecutionLogger) -> None:
        self._policy = policy
        self._logger = execution_logger

    def execute(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        iteration: int,
    ) -> dict[str, Any]:
        """Execute a tool call with full policy check and logging.

        Returns the tool output dict. If blocked by policy, returns error dict.
        """
        call_id = f"call_{uuid.uuid4().hex[:8]}"

        # Log outgoing call
        self._logger.log_tool_call(
            iteration=iteration,
            tool_name=tool_name,
            tool_input=tool_input,
            call_id=call_id,
        )

        # Policy check
        policy_decision = self._policy.check_tool_call(
            tool_name=tool_name,
            tool_input=tool_input,
            current_iteration=iteration,
        )

        if not policy_decision.allowed:
            logger.warning(
                "tool_call_blocked",
                tool=tool_name,
                reason=policy_decision.reason,
            )
            self._logger.log_tool_result(
                iteration=iteration,
                tool_name=tool_name,
                call_id=call_id,
                output_size=0,
                output_hash="",
                duration_ms=0,
                success=False,
            )
            return {
                "error": f"BLOCKED: {policy_decision.reason}",
                "tool": tool_name,
                "call_id": call_id,
            }

        # Dispatch to actual tool
        tool_func = TOOL_REGISTRY.get(tool_name)
        if tool_func is None:
            error_result = {
                "error": f"Unknown tool: {tool_name}. Available: {list(TOOL_REGISTRY.keys())}",
                "call_id": call_id,
            }
            self._logger.log_tool_result(
                iteration=iteration,
                tool_name=tool_name,
                call_id=call_id,
                output_size=0,
                output_hash="",
                duration_ms=0,
                success=False,
            )
            return error_result

        # Execute
        start = time.time()
        try:
            result = tool_func(**tool_input)
            duration_ms = (time.time() - start) * 1000

            # Compute output hash for audit trail
            output_str = str(result)
            output_hash = hashlib.sha256(output_str.encode()).hexdigest()[:16]

            result["call_id"] = call_id

            self._logger.log_tool_result(
                iteration=iteration,
                tool_name=tool_name,
                call_id=call_id,
                output_size=len(output_str),
                output_hash=output_hash,
                duration_ms=duration_ms,
                success=True,
            )

            logger.info(
                "tool_executed",
                tool=tool_name,
                call_id=call_id,
                duration_ms=round(duration_ms),
                output_size=len(output_str),
            )

            return result

        except Exception as e:
            duration_ms = (time.time() - start) * 1000
            logger.error("tool_execution_failed", tool=tool_name, error=str(e))
            self._logger.log_tool_result(
                iteration=iteration,
                tool_name=tool_name,
                call_id=call_id,
                output_size=0,
                output_hash="",
                duration_ms=duration_ms,
                success=False,
            )
            return {"error": str(e), "tool": tool_name, "call_id": call_id}
