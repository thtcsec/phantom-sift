"""LLM Client — Anthropic Claude integration with Cloudflare AI Gateway.

Handles:
- Claude API calls (tool-use mode)
- Transparent proxy through Cloudflare AI Gateway when configured
- Token counting and logging
- Retry logic for transient failures
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import anthropic
import structlog

from ..config import Settings
from ..integrations.cloudflare_gateway import CloudflareGatewayConfig

logger = structlog.get_logger()


@dataclass
class LLMResponse:
    """Structured response from LLM call."""

    content_blocks: list[dict[str, Any]] = field(default_factory=list)
    stop_reason: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""
    duration_ms: float = 0

    @property
    def text_content(self) -> str:
        """Extract all text content blocks joined."""
        parts = []
        for block in self.content_blocks:
            if block.get("type") == "text":
                parts.append(block["text"])
        return "\n".join(parts)

    @property
    def tool_calls(self) -> list[dict[str, Any]]:
        """Extract tool_use blocks from response."""
        return [b for b in self.content_blocks if b.get("type") == "tool_use"]

    @property
    def has_tool_calls(self) -> bool:
        return len(self.tool_calls) > 0


class LLMClient:
    """Anthropic Claude client with CF AI Gateway proxy.

    Usage:
        client = LLMClient(settings)
        response = client.chat(messages, tools, system)
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._model = settings.agent_model
        self._max_retries = 3

        # Configure Cloudflare AI Gateway proxy
        gateway = CloudflareGatewayConfig(settings)
        client_kwargs = gateway.get_client_kwargs()

        self._client = anthropic.Anthropic(
            api_key=settings.anthropic_api_key,
            **client_kwargs,
        )

        if gateway.is_enabled:
            logger.info("llm_client_initialized", proxy="cloudflare_ai_gateway")
        else:
            logger.info("llm_client_initialized", proxy="direct")

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str = "",
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send a message to Claude and get a response.

        Supports tool-use mode: Claude can request tool calls in its response.

        Args:
            messages: Conversation history (role/content pairs)
            tools: Available tools in Anthropic tool schema format
            system: System prompt
            max_tokens: Max output tokens

        Returns:
            LLMResponse with content blocks, token usage, timing
        """
        start = time.time()

        kwargs: dict[str, Any] = {
            "model": self._model,
            "max_tokens": max_tokens,
            "messages": messages,
        }
        if system:
            kwargs["system"] = system
        if tools:
            kwargs["tools"] = tools

        for attempt in range(1, self._max_retries + 1):
            try:
                response = self._client.messages.create(**kwargs)
                duration_ms = (time.time() - start) * 1000

                result = LLMResponse(
                    content_blocks=[block.model_dump() for block in response.content],
                    stop_reason=response.stop_reason or "",
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                    model=response.model,
                    duration_ms=duration_ms,
                )

                logger.info(
                    "llm_call_complete",
                    model=response.model,
                    input_tokens=result.input_tokens,
                    output_tokens=result.output_tokens,
                    stop_reason=result.stop_reason,
                    duration_ms=round(duration_ms),
                    tool_calls=len(result.tool_calls),
                )

                return result

            except anthropic.RateLimitError:
                wait = 2**attempt
                logger.warning("llm_rate_limited", attempt=attempt, wait_seconds=wait)
                time.sleep(wait)

            except anthropic.APIConnectionError as e:
                if attempt == self._max_retries:
                    raise
                logger.warning("llm_connection_error", attempt=attempt, error=str(e))
                time.sleep(1)

        # Should not reach here, but just in case
        raise RuntimeError("LLM call failed after all retries")
