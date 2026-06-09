# Architecture — Phantom SIFT

## Architectural Pattern: Custom MCP Server + Direct Agent Extension

Phantom SIFT uses **Pattern 2 (Custom MCP Server)** as primary architecture with
elements of Pattern 1 (Direct Agent Extension) for the reasoning loop.

## Component Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SANS SIFT Workstation                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────┐                                               │
│  │   CLI Entry       │  phantom-sift analyze --case /evidence/...    │
│  └────────┬─────────┘                                               │
│           ▼                                                          │
│  ┌──────────────────┐    ┌──────────────────────────────────────┐   │
│  │   Agent Loop      │───▶│  Policy Engine (Guardrails)           │   │
│  │   (Reasoning)     │    │  • No write tools                    │   │
│  │                   │    │  • No path traversal                 │   │
│  │   • Plan phase    │    │  • Max iterations                    │   │
│  │   • Execute tool  │    │  • Evidence boundary                 │   │
│  │   • Evaluate      │    └──────────────────────────────────────┘   │
│  │   • Self-correct  │                                               │
│  └────────┬─────────┘                                               │
│           │                                                          │
│     ┌─────┴──────┐                                                   │
│     ▼            ▼                                                   │
│  ┌────────┐  ┌────────────────────────────────────┐                  │
│  │ LLM    │  │  Local MCP Server                   │                  │
│  │ Client │  │  (FastMCP — typed functions)         │                  │
│  └───┬────┘  │                                     │                  │
│      │       │  Filesystem: mmls, fls, icat, fsstat │                  │
│      │       │  Timeline: mactime, log2timeline     │                  │
│      │       │  Memory: vol3 pslist/pstree/malfind  │                  │
│      │       │  Registry: regripper, amcache        │                  │
│      │       │  Strings: strings, yara              │                  │
│      │       │  Network: tshark, zeek               │                  │
│      │       └──────────────┬──────────────────────┘                  │
│      │                      │                                         │
│      │                      ▼                                         │
│      │              ┌───────────────────┐                             │
│      │              │ SIFT Tools (CLI)   │  200+ forensic utilities   │
│      │              │ Read-only access   │                            │
│      │              └───────────────────┘                             │
│      │                                                                │
│      │    Cloudflare AI Gateway (proxy)                               │
│      └──────────────────────┐                                         │
│                             ▼                                         │
└─────────────────────────────┼─────────────────────────────────────────┘
                              │ HTTPS (network boundary)
                    ┌─────────┴─────────┐
                    ▼                   ▼
          ┌──────────────┐   ┌──────────────────────┐
          │ Anthropic API │   │ CF Workers Remote MCP │
          │ (Claude)      │   │ • threat_intel_hash   │
          └──────────────┘   │ • threat_intel_ip     │
                             │ • report_finding      │
                             └──────────────────────┘
```

## Security Boundaries

| Layer | Enforcement Type | What It Prevents |
|-------|-----------------|-----------------|
| MCP Server tool definitions | **Architectural** | No write/delete/shell tools exist |
| PolicyEngine.check_tool_call() | **Architectural** | Path traversal, iteration overflow |
| Evidence hash verification | **Architectural** | Detects any modification post-analysis |
| Cloudflare AI Gateway rate limit | **Infrastructure** | Runaway agent spending |
| LLM system prompt | **Prompt-based** ⚠️ | Hallucinations (unreliable — that's why self-correction exists) |

## Data Flow

```
Evidence File (read-only)
    │
    ├──▶ MCP Tool (subprocess, stdout captured)
    │        │
    │        ▼
    │    Tool Output (text)
    │        │
    │        ▼
    │    Agent (Claude via AI Gateway)
    │        │
    │        ├──▶ New Finding (structured)
    │        ├──▶ Next Tool Call (back to MCP)
    │        └──▶ Self-Correction (revise finding)
    │
    └── Evidence Hash unchanged ✓ (verified at end)
```

## Cloudflare Integration Points

1. **AI Gateway** — All Claude API calls proxied through CF edge
   - Token counting (automatic)
   - Request/response logging (automatic)
   - Cache identical prompts (saves $)
   - Rate limiting (prevents runaway)

2. **Workers (Remote MCP)** — Threat intelligence at edge
   - API keys stored in CF Workers secrets (not on SIFT VM)
   - Provides VT/AbuseIPDB lookups as MCP tools
   - Network boundary: agent on SIFT → CF Workers → external APIs

3. **Workers AI** (future) — Secondary model cross-validation
   - Run Llama 3.3 70B on CF for independent finding verification
   - If Claude says X and Llama agrees → higher confidence
