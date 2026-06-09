# Dataset Documentation — Phantom SIFT

## Evidence Sources

> **Status:** Template — to be updated with actual test data before submission.

### Planned Test Data

| Dataset | Type | Source | Ground Truth |
|---------|------|--------|--------------|
| SANS DFIR Challenge (2024) | Disk image | SANS.org | Published solution |
| Volatility Foundation samples | Memory dump | volatilityfoundation.org | Documented malware |
| PCAP samples (malware-traffic-analysis) | Network capture | malware-traffic-analysis.net | Annotated |
| Protocol SIFT starter data | Mixed | Hackathon Slack channel | Provided by organizers |

### Evidence Handling

1. Evidence is **never modified** (SHA256 verified pre/post)
2. Evidence is mounted **read-only** at `/mnt/evidence`
3. All analysis runs on a copy if needed (e.g., for mounting)

### What the Agent Was Tested Against

| Case | Key Artifacts | Expected Findings | Agent Detected? |
|------|---------------|-------------------|-----------------|
| TODO | TODO | TODO | TODO |

## Reproducibility

To reproduce results:

```bash
# 1. Download evidence (links in hackathon Slack)
wget -O /mnt/evidence/case1.dd <URL>

# 2. Verify hash matches documented value
sha256sum /mnt/evidence/case1.dd

# 3. Run agent
phantom-sift analyze --case /mnt/evidence/case1.dd --max-iterations 15

# 4. Compare output report with ground truth
diff reports/report_*.md docs/ground-truth/case1-expected.md
```
