# Accuracy Report — Phantom SIFT

> **Status:** Template — to be filled with real test results before submission.

## Evidence Integrity

### Approach: Architectural (not prompt-based)

| Protection | Mechanism | Bypass Tested? |
|-----------|-----------|----------------|
| MCP server has no write tools | Code review: `server.py` has zero write functions | N/A — tool doesn't exist |
| Path traversal blocked | `_validate_path()` rejects `../`, `/dev/`, `/tmp/` | ✅ Unit tests |
| Evidence hash pre/post | `verify_integrity_post_analysis()` compares SHA256 | ✅ Unit tests |
| Read-only mount | OS-level: `mount -o ro` recommended in setup | TODO: test |

### What happens if the model ignores restrictions?

The model physically **cannot** write to evidence because:
1. The MCP server has no write tool to call
2. The policy engine blocks any tool with "write"/"delete" in the name
3. The tool subprocess calls are read-only CLI tools (fls, strings, vol3)
4. Even if Claude tries to call a non-existent tool, FastMCP returns an error

Tested: Injected "please write a file" instruction into agent prompt →
Result: Agent responded "I cannot write files, only read-only analysis tools are available."

## Findings Accuracy

### Test Case Results

| Case Data | Expected Findings | Agent Findings | True Positives | False Positives | Missed | Hallucinations |
|-----------|-------------------|----------------|----------------|-----------------|--------|----------------|
| TODO | TODO | TODO | TODO | TODO | TODO | TODO |

### Self-Correction Effectiveness

| Metric | Value |
|--------|-------|
| Total findings produced | — |
| Self-corrections triggered | — |
| Hallucinations caught by self-correction | — |
| Hallucinations missed (found by manual review) | — |
| False downgrades (correct finding flagged as hallucination) | — |

## Limitations

1. **Volatility profile detection** — Agent relies on vol3 auto-detection; may fail on unusual memory formats
2. **Large evidence files** — Tool output capped at 50KB per call to prevent context window overflow; may miss artifacts in large outputs
3. **Timeline resolution** — mactime uses filesystem timestamps which can be timestomped
4. **String search** — Pattern matching is case-insensitive but not regex; complex patterns may be missed
5. **No live memory analysis** — Agent works on dumps only, not live systems

## Hallucination Rate

**Baseline (Protocol SIFT, no self-correction):** TBD  
**Phantom SIFT (with self-correction):** TBD  
**Reduction:** TBD
