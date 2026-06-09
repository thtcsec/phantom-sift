"""Cloudflare AI Gateway — LLM proxy with built-in observability.

Routes all Anthropic API calls through Cloudflare's edge network:
- Automatic logging of every request/response (token counts, latency)
- Response caching for identical prompts (saves cost during iteration)
- Rate limiting at network layer (prevents runaway agent)
- Dashboard visibility: https://dash.cloudflare.com → AI → AI Gateway

This directly satisfies hackathon requirement #8:
  "Agent execution logs with timestamps and token usage"
  → Cloudflare AI Gateway provides this automatically at infrastructure level.

Usage:
    Instead of: base_url="https://api.anthropic.com"
    Use:        base_url="https://gateway.ai.cloudflare.com/v1/{account}/{gateway}/anthropic"
"""

from __future__ import annotations

from typing import Any

import structlog

from ..config import Settings

logger = structlog.get_logger()


class CloudflareGatewayConfig:
    """Configuration helper for Cloudflare AI Gateway integration.

    When configured, transparently proxies all Claude API calls through
    Cloudflare's edge for observability without any code changes to
    the Anthropic client.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    @property
    def is_enabled(self) -> bool:
        """Check if AI Gateway is configured."""
        return self._settings.cloudflare_gateway_base_url is not None

    @property
    def base_url(self) -> str | None:
        """Get the gateway proxy URL for Anthropic."""
        return self._settings.cloudflare_gateway_base_url

    def get_client_kwargs(self) -> dict[str, Any]:
        """Get kwargs to pass to anthropic.Anthropic() constructor.

        Usage:
            from anthropic import Anthropic
            gateway = CloudflareGatewayConfig(settings)
            client = Anthropic(
                api_key=settings.anthropic_api_key,
                **gateway.get_client_kwargs()
            )
        """
        kwargs: dict[str, Any] = {}
        if self.is_enabled:
            kwargs["base_url"] = self.base_url
            logger.info(
                "cloudflare_ai_gateway_enabled",
                gateway_id=self._settings.cloudflare_ai_gateway_id,
            )
        else:
            logger.info("cloudflare_ai_gateway_disabled", reason="not configured")
        return kwargs

    @property
    def dashboard_url(self) -> str:
        """URL to view execution logs in Cloudflare dashboard."""
        if self._settings.cloudflare_account_id:
            return (
                f"https://dash.cloudflare.com/"
                f"{self._settings.cloudflare_account_id}/ai/ai-gateway/"
                f"{self._settings.cloudflare_ai_gateway_id}"
            )
        return "https://dash.cloudflare.com → AI → AI Gateway"
