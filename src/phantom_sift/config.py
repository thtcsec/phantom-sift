"""Configuration management for Phantom SIFT.

Loads settings from environment variables (.env) with sensible defaults.
Pattern adapted from SOAR repos' config management.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field

try:
    from pydantic_settings import BaseSettings
except ImportError:
    # Fallback if pydantic-settings not installed yet
    from pydantic import BaseModel as BaseSettings  # type: ignore[assignment]


class Settings(BaseSettings):
    """Application settings loaded from environment."""

    # LLM
    anthropic_api_key: str = Field(default="", description="Anthropic API key")
    agent_model: str = Field(default="claude-sonnet-4-20250514", description="Model to use")
    agent_temperature: float = Field(default=0.1, description="LLM temperature")
    agent_max_iterations: int = Field(default=15, description="Max agent loop iterations")

    # Cloudflare AI Gateway
    cloudflare_account_id: str = Field(default="", description="CF account ID")
    cloudflare_ai_gateway_id: str = Field(default="phantom-sift", description="CF AI Gateway ID")

    # Cloudflare Workers AI (optional secondary model)
    cloudflare_workers_ai_token: str = Field(default="", description="CF Workers AI token")

    # Remote MCP
    remote_mcp_url: str = Field(default="", description="Remote MCP server URL on CF Workers")

    # Threat Intelligence
    virustotal_api_key: str = Field(default="", description="VirusTotal API key")
    abuseipdb_api_key: str = Field(default="", description="AbuseIPDB API key")

    # Evidence
    evidence_mount_path: Path = Field(default=Path("/mnt/evidence"), description="Evidence mount")
    evidence_read_only: bool = Field(default=True, description="Enforce read-only evidence access")

    # Logging
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(default="INFO")
    log_format: Literal["json", "console"] = Field(default="json")
    execution_log_path: Path = Field(
        default=Path("./logs/execution.jsonl"), description="Agent execution log"
    )

    @property
    def cloudflare_gateway_base_url(self) -> str | None:
        """Construct CF AI Gateway proxy URL. Returns None if not configured."""
        if self.cloudflare_account_id and self.cloudflare_ai_gateway_id:
            return (
                f"https://gateway.ai.cloudflare.com/v1/"
                f"{self.cloudflare_account_id}/{self.cloudflare_ai_gateway_id}/anthropic"
            )
        return None

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


def get_settings() -> Settings:
    """Get application settings singleton."""
    return Settings()
