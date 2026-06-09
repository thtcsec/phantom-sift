<p align="center">
  <img src="docs/images/phantom-sift-banner.png" alt="Phantom SIFT" width="720">
</p>

# 👻 Phantom SIFT — Autonomous DFIR Agent on SANS SIFT Workstation

![SANS SIFT](https://img.shields.io/badge/SANS-SIFT%20Workstation-blue?style=for-the-badge)
![MCP](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-purple?style=for-the-badge)
![Cloudflare](https://img.shields.io/badge/Cloudflare-AI%20Gateway-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)
![Python](https://img.shields.io/badge/python-3.11+-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![License](https://img.shields.io/badge/License-Apache%202.0-green?style=for-the-badge)

**Self-correcting AI agent for digital forensics and incident response.** Extends Protocol SIFT with a custom MCP server exposing typed forensic tools, a reasoning agent loop with iterative self-correction, and Cloudflare AI Gateway for full execution observability.

> 🏆 **SANS Find Evil! Hackathon 2026** — Built for autonomous incident response at machine speed.

---

## 🎯 What It Does

Phantom SIFT takes a forensic case (disk image, memory dump, log files) and autonomously:

1. **Triages** — Runs initial forensic tools to establish timeline and artifacts
2. **Reasons** — Determines what's suspicious, what needs deeper analysis
3. **Self-corrects** — Detects inconsistencies in its own findings, re-runs with adjusted parameters
4. **Reports** — Produces structured findings with full evidence chain (artifact → offset → tool → conclusion)

```
"find evil" → Agent reasons → Calls SIFT tools via MCP → Evaluates output →
    → Detects gaps/inconsistencies → Re-runs with different approach →
    → Produces verified findings with confidence scores
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SANS SIFT Workstation                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐    ┌──────────────────┐    ┌──────────────────┐  │
│  │  Agent Loop  │───▶│  Local MCP Server │───▶│  SIFT Tools      │  │
│  │  (Reasoner)  │    │  (Typed Functions)│    │  200+ utilities  │  │
│  └──────┬───────┘    └──────────────────┘    └──────────────────┘  │
│         │                                                           │
│         │ LLM calls                                                 │
│         ▼                                                           │
│  ┌──────────────────────────────────────┐                          │
│  │     Cloudflare AI Gateway            │  ◀── Logs, tokens,       │
│  │     (Proxy + Observability)          │      caching, metrics    │
│  └──────────────┬───────────────────────┘                          │
│                 │                                                    │
└─────────────────┼────────────────────────────────────────────────────┘
                  │
                  ▼
         ┌────────────────┐         ┌─────────────────────────┐
         │  Anthropic API │         │  Cloudflare Workers      │
         │  (Claude)      │         │  Remote MCP Server       │
         └────────────────┘         │  - Threat Intel (VT/IP)  │
                                    │  - Report endpoint       │
                                    │  - SOAR bridge (future)  │
                                    └─────────────────────────┘
```

### Architectural Guardrails (Not Prompt-Based)

| Boundary | Enforcement |
|----------|------------|
| Evidence integrity | MCP server exposes **read-only** tools only. No write/delete functions exist. |
| Destructive commands | MCP server has no `execute_shell_cmd`. Tools are typed: `get_mft_entries()`, not `run("ntfsinfo ...")` |
| Agent cannot bypass | Tool functions validate inputs, reject path traversal, enforce read-only mounts |
| Token budget | Cloudflare AI Gateway enforces rate limits at network layer |
| Runaway prevention | Agent loop has hard `--max-iterations` cap with graceful degradation |

### Trust Boundaries

```
┌─ TRUSTED (our code) ─────────────────────────────────┐
│  MCP Server → validates all inputs                    │
│  Agent Loop → bounded iterations, structured output   │
│  Execution Logger → immutable append-only             │
└───────────────────────────────────────────────────────┘
         │
         ▼ (network boundary)
┌─ EXTERNAL (not our code) ─────────────────────────────┐
│  LLM (Claude) → may hallucinate, may ignore rules     │
│  → That's why self-correction exists                  │
│  → That's why MCP has no destructive tools            │
└───────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- SANS SIFT Workstation (OVA or bare metal)
- Python 3.11+
- Protocol SIFT installed (`curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash`)
- Anthropic API key
- (Optional) Cloudflare account for AI Gateway

### Installation

```bash
git clone https://github.com/thtcsec/phantom-sift.git
cd phantom-sift

python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Configure
cp .env.example .env
# Edit .env with your API keys
```

### Run Agent

```bash
# Analyze a disk image
phantom-sift analyze --case /path/to/evidence.dd --max-iterations 10

# Analyze memory dump
phantom-sift analyze --case /path/to/memory.vmem --type memory

# Dry run (no LLM calls, validate MCP tools)
phantom-sift doctor
```

---

## 📂 Project Structure

```
phantom-sift/
├── src/
│   ├── phantom_sift/
│   │   ├── __init__.py
│   │   ├── cli.py                  # CLI entry point
│   │   ├── agent/
│   │   │   ├── __init__.py
│   │   │   ├── loop.py            # Core agent reasoning loop
│   │   │   ├── self_correction.py # Consistency checker + re-run logic
│   │   │   ├── prompts.py         # System prompts (analyst persona)
│   │   │   └── planner.py         # Tool sequencing strategy
│   │   ├── mcp_server/
│   │   │   ├── __init__.py
│   │   │   ├── server.py          # FastMCP server definition
│   │   │   └── tools/
│   │   │       ├── __init__.py
│   │   │       ├── filesystem.py  # fls, mmls, icat, fstat
│   │   │       ├── timeline.py    # mactime, log2timeline/plaso
│   │   │       ├── memory.py      # volatility3 wrappers
│   │   │       ├── registry.py    # regripper, amcache
│   │   │       ├── network.py     # tshark, zeek
│   │   │       └── strings.py     # strings, yara
│   │   ├── core/
│   │   │   ├── __init__.py
│   │   │   ├── findings.py        # ForensicFinding schema
│   │   │   ├── evidence.py        # Evidence mount + integrity check
│   │   │   ├── audit_logger.py    # Execution trail (from SOAR pattern)
│   │   │   └── policy.py          # Guardrails + decision gate (from SOAR)
│   │   ├── integrations/
│   │   │   ├── __init__.py
│   │   │   ├── cloudflare_gateway.py  # AI Gateway client wrapper
│   │   │   ├── threat_intel.py        # VT + AbuseIPDB (from SOAR)
│   │   │   └── reporting.py           # Structured report generator
│   │   └── config.py              # Settings + env loading
│   └── remote_mcp/                # Cloudflare Workers (TypeScript)
│       ├── package.json
│       ├── wrangler.toml
│       ├── tsconfig.json
│       └── src/
│           └── index.ts           # Remote MCP: threat intel + reporting
├── tests/
│   ├── __init__.py
│   ├── test_mcp_tools.py
│   ├── test_agent_loop.py
│   ├── test_self_correction.py
│   └── test_findings.py
├── docs/
│   ├── architecture.md
│   ├── accuracy-report.md
│   ├── dataset-documentation.md
│   └── images/
├── logs/
│   └── .gitkeep
├── prompts/
│   └── analyst_system.md          # Senior analyst persona
├── pyproject.toml
├── .env.example
├── .gitignore
├── LICENSE
└── README.md
```

---

## 🔑 Key Design Decisions

### From SOAR (Patterns Adapted)

| SOAR Pattern | Phantom SIFT Adaptation |
|---|---|
| `PlaybookRegistry.dispatch()` | → `ToolRegistry` — MCP tool routing |
| `IncidentPipeline.process()` | → `AgentLoop.run()` — reason → act → verify cycle |
| `AuditLogger` | → `ExecutionLogger` — structured agent logs with timestamps + tokens |
| `PolicyEngine` (decision gate) | → `Policy` — guardrails before tool execution |
| `UnifiedIncident` schema | → `ForensicFinding` — artifact, offset, confidence, tool_source |
| `ScoringEngine` | → `ConfidenceScorer` — finding confidence based on corroboration |

### Cloudflare Integration

| Component | Role |
|---|---|
| **AI Gateway** | Proxy all Claude API calls → auto-log tokens, latency, cache identical prompts |
| **Workers (Remote MCP)** | Edge-deployed threat intel lookup + report storage — no local API keys needed |
| **Workers AI** (optional) | Secondary model for cross-validation of findings |

---

## 📊 Judging Criteria Mapping

| Criteria | How Phantom SIFT Addresses It |
|----------|------------------------------|
| **Autonomous Execution Quality** | Agent loop with planner → executor → verifier cycle; self-correction on inconsistency |
| **IR Accuracy** | Findings have confidence scores; hallucinations flagged when tool output contradicts claim |
| **Breadth/Depth** | Filesystem + timeline + memory + registry + network tools via MCP |
| **Constraint Implementation** | Architectural: MCP has no write tools, no shell exec; network boundary via CF Gateway |
| **Audit Trail** | Every tool call logged with timestamp, input, output hash, token count (CF AI Gateway) |
| **Usability** | Single CLI command; runs on stock SIFT Workstation; `phantom-sift doctor` validates setup |

---

## 🔮 Future Work

- Connect confirmed IOCs to cloud SOAR playbooks via MCP for automated remediation
  (see [AWS-Serverless-SOAR](https://github.com/thtcsec/AWS-Serverless-SOAR), [GCP-Serverless-SOAR](https://github.com/thtcsec/GCP-Serverless-SOAR))
- Multi-agent decomposition (memory specialist + disk specialist + correlator)
- Persistent learning loop across cases
- MITRE ATT&CK TTP auto-mapping per finding

---

## 👤 Author

**thtcsec** — Cloudflare Ambassador | Cloud Security Engineer

---

## 📄 License

Apache License 2.0 — See [LICENSE](LICENSE)
