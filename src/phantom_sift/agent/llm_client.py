"""LLM Client — Multi-provider support with Cloudflare AI Gateway.

Supports:
- Cloudflare Workers AI (FREE — default, 10K neurons/day)
- Anthropic Claude (best quality, expensive)
- OpenAI-compatible (Groq, Together, Ollama, etc.)

All providers can be proxied through Cloudflare AI Gateway for
automatic logging, caching, and observability.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx
import structlog

from ..config import Settings
from ..integrations.cloudflare_gateway import CloudflareGatewayConfig

logger = structlog.get_logger()

LLMProvider = Literal["workers-ai", "anthropic", "openai"]


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
                parts.append(block.get("text", ""))
        return "\n".join(parts)

    @property
    def tool_calls(self) -> list[dict[str, Any]]:
        """Extract tool_use blocks from response."""
        return [b for b in self.content_blocks if b.get("type") == "tool_use"]

    @property
    def has_tool_calls(self) -> bool:
        return len(self.tool_calls) > 0


class LLMClient:
    """Multi-provider LLM client with Cloudflare AI Gateway proxy.

    Usage:
        client = LLMClient(settings)
        response = client.chat(messages, tools, system)

    Provider selection via settings.llm_provider:
        - "workers-ai": Cloudflare Workers AI (FREE, Llama 3.3 70B)
        - "anthropic": Claude Sonnet (best quality)
        - "openai": OpenAI-compatible (Groq, Together, Ollama)
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._model = settings.agent_model
        self._provider = settings.llm_provider
        self._max_retries = 3
        self._gateway = CloudflareGatewayConfig(settings)

        # Initialize provider-specific client
        if self._provider == "anthropic":
            self._init_anthropic()
        elif self._provider == "workers-ai":
            self._init_workers_ai()
        elif self._provider == "openai":
            self._init_openai()

        logger.info(
            "llm_client_initialized",
            provider=self._provider,
            model=self._model,
            gateway="cloudflare" if self._gateway.is_enabled else "direct",
        )

    def _init_anthropic(self) -> None:
        """Initialize Anthropic client."""
        import anthropic

        client_kwargs = self._gateway.get_client_kwargs()
        self._anthropic = anthropic.Anthropic(
            api_key=self._settings.anthropic_api_key,
            **client_kwargs,
        )

    def _init_workers_ai(self) -> None:
        """Initialize Cloudflare Workers AI client (REST API)."""
        self._cf_account_id = self._settings.cloudflare_account_id
        self._cf_token = self._settings.cloudflare_workers_ai_token
        if not self._cf_account_id or not self._cf_token:
            raise ValueError(
                "Workers AI requires CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_WORKERS_AI_TOKEN"
            )
        self._workers_ai_base = (
            f"https://api.cloudflare.com/client/v4/accounts/{self._cf_account_id}/ai/run"
        )

    def _init_openai(self) -> None:
        """Initialize OpenAI-compatible client (Groq, Together, Ollama, etc.)."""
        self._openai_base = self._settings.openai_base_url
        self._openai_key = self._settings.openai_api_key

    # ─── Main Chat Method ─────────────────────────────────────────────

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str = "",
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send a message to the LLM and get a response.

        Supports tool-use mode across all providers.
        Routes to the appropriate provider implementation.
        """
        if self._provider == "anthropic":
            return self._chat_anthropic(messages, tools, system, max_tokens)
        elif self._provider == "workers-ai":
            return self._chat_workers_ai(messages, tools, system, max_tokens)
        elif self._provider == "openai":
            return self._chat_openai(messages, tools, system, max_tokens)
        else:
            raise ValueError(f"Unknown provider: {self._provider}")

    # ─── Anthropic Implementation ─────────────────────────────────────

    def _chat_anthropic(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        system: str,
        max_tokens: int,
    ) -> LLMResponse:
        """Call Anthropic Claude API with tool-use support."""
        import anthropic

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
                response = self._anthropic.messages.create(**kwargs)
                duration_ms = (time.time() - start) * 1000

                return LLMResponse(
                    content_blocks=[block.model_dump() for block in response.content],
                    stop_reason=response.stop_reason or "",
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                    model=response.model,
                    duration_ms=duration_ms,
                )
            except anthropic.RateLimitError:
                time.sleep(2**attempt)
            except anthropic.APIConnectionError:
                if attempt == self._max_retries:
                    raise
                time.sleep(1)

        raise RuntimeError("Anthropic call failed after retries")

    # ─── Workers AI Implementation ────────────────────────────────────

    def _chat_workers_ai(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        system: str,
        max_tokens: int,
    ) -> LLMResponse:
        """Call Cloudflare Workers AI with function calling.

        Workers AI uses OpenAI-compatible format for tool calling.
        Model: @cf/meta/llama-3.3-70b-instruct-fp8-fast (FREE)
        """
        start = time.time()
        model = self._model or "@cf/meta/llama-3.3-70b-instruct-fp8-fast"

        # Build messages in OpenAI format (Workers AI is OpenAI-compatible)
        cf_messages = []
        if system:
            cf_messages.append({"role": "system", "content": system})

        for msg in messages:
            cf_messages.append(self._convert_message_to_openai(msg))

        payload: dict[str, Any] = {
            "messages": cf_messages,
            "max_tokens": max_tokens,
            "temperature": self._settings.agent_temperature,
        }

        # Add tools in OpenAI format
        if tools:
            payload["tools"] = self._convert_tools_to_openai(tools)

        url = f"{self._workers_ai_base}/{model}"

        for attempt in range(1, self._max_retries + 1):
            try:
                with httpx.Client(timeout=120.0) as client:
                    resp = client.post(
                        url,
                        headers={"Authorization": f"Bearer {self._cf_token}"},
                        json=payload,
                    )

                if resp.status_code == 429:
                    time.sleep(2**attempt)
                    continue

                resp.raise_for_status()
                data = resp.json()
                duration_ms = (time.time() - start) * 1000

                return self._parse_workers_ai_response(data, model, duration_ms)

            except httpx.HTTPStatusError as e:
                if attempt == self._max_retries:
                    raise RuntimeError(f"Workers AI failed: {e.response.text}") from e
                time.sleep(1)

        raise RuntimeError("Workers AI call failed after retries")

    def _parse_workers_ai_response(
        self, data: dict[str, Any], model: str, duration_ms: float
    ) -> LLMResponse:
        """Parse Workers AI response into our standard LLMResponse."""
        result = data.get("result", {})
        response_msg = result.get("response", "")

        # Handle tool calls (OpenAI format)
        tool_calls_raw = result.get("tool_calls", [])

        content_blocks: list[dict[str, Any]] = []

        if response_msg:
            content_blocks.append({"type": "text", "text": response_msg})

        for tc in tool_calls_raw:
            func = tc.get("function", {})
            args = func.get("arguments", "{}")
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}

            content_blocks.append({
                "type": "tool_use",
                "id": tc.get("id", f"call_{int(time.time())}"),
                "name": func.get("name", ""),
                "input": args,
            })

        # Token estimates (Workers AI doesn't always return exact counts)
        input_tokens = result.get("usage", {}).get("prompt_tokens", 0)
        output_tokens = result.get("usage", {}).get("completion_tokens", 0)

        return LLMResponse(
            content_blocks=content_blocks,
            stop_reason="tool_use" if tool_calls_raw else "end_turn",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=model,
            duration_ms=duration_ms,
        )

    # ─── OpenAI-Compatible Implementation ─────────────────────────────

    def _chat_openai(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        system: str,
        max_tokens: int,
    ) -> LLMResponse:
        """Call OpenAI-compatible API (Groq, Together, Ollama, etc.)."""
        start = time.time()

        oai_messages = []
        if system:
            oai_messages.append({"role": "system", "content": system})
        for msg in messages:
            oai_messages.append(self._convert_message_to_openai(msg))

        payload: dict[str, Any] = {
            "model": self._model,
            "messages": oai_messages,
            "max_tokens": max_tokens,
            "temperature": self._settings.agent_temperature,
        }
        if tools:
            payload["tools"] = self._convert_tools_to_openai(tools)

        url = f"{self._openai_base}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self._openai_key:
            headers["Authorization"] = f"Bearer {self._openai_key}"

        with httpx.Client(timeout=120.0) as client:
            resp = client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()

        duration_ms = (time.time() - start) * 1000
        choice = data.get("choices", [{}])[0]
        msg = choice.get("message", {})

        content_blocks: list[dict[str, Any]] = []
        if msg.get("content"):
            content_blocks.append({"type": "text", "text": msg["content"]})

        for tc in msg.get("tool_calls", []):
            func = tc.get("function", {})
            args = func.get("arguments", "{}")
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            content_blocks.append({
                "type": "tool_use",
                "id": tc.get("id", f"call_{int(time.time())}"),
                "name": func.get("name", ""),
                "input": args,
            })

        usage = data.get("usage", {})
        return LLMResponse(
            content_blocks=content_blocks,
            stop_reason="tool_use" if msg.get("tool_calls") else "end_turn",
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            model=data.get("model", self._model),
            duration_ms=duration_ms,
        )

    # ─── Format Converters ────────────────────────────────────────────

    def _convert_message_to_openai(self, msg: dict[str, Any]) -> dict[str, Any]:
        """Convert Anthropic-style message to OpenAI format."""
        role = msg.get("role", "user")
        content = msg.get("content", "")

        if isinstance(content, str):
            return {"role": role, "content": content}

        if isinstance(content, list):
            # Handle Anthropic content blocks
            parts = []
            tool_calls = []
            for block in content:
                if isinstance(block, dict):
                    if block.get("type") == "text":
                        parts.append(block.get("text", ""))
                    elif block.get("type") == "tool_use":
                        tool_calls.append({
                            "id": block.get("id", ""),
                            "type": "function",
                            "function": {
                                "name": block.get("name", ""),
                                "arguments": json.dumps(block.get("input", {})),
                            },
                        })
                    elif block.get("type") == "tool_result":
                        # Tool results become separate messages in OpenAI format
                        return {
                            "role": "tool",
                            "tool_call_id": block.get("tool_use_id", ""),
                            "content": block.get("content", ""),
                        }

            if tool_calls:
                result: dict[str, Any] = {"role": "assistant"}
                if parts:
                    result["content"] = "\n".join(parts)
                result["tool_calls"] = tool_calls
                return result

            return {"role": role, "content": "\n".join(parts) if parts else ""}

        return {"role": role, "content": str(content)}

    def _convert_tools_to_openai(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Convert Anthropic tool format to OpenAI format."""
        openai_tools = []
        for tool in tools:
            openai_tools.append({
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "parameters": tool.get("input_schema", {}),
                },
            })
        return openai_tools
