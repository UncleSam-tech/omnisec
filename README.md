# OmniSec (Unified Threat Normalizer)

OmniSec is an **Execute-Mode Model Context Protocol (MCP) tool** built specifically to unify fragmented enterprise security platforms (VirusTotal, GreyNoise, AbuseIPDB) into a single deterministic schema for autonomous AI Agents.

By utilizing the developer's proprietary environment keys, OmniSec structurally bypasses the "Public Data Trap," mathematically parsing complex intelligence drops into a single **A-F Actionable Risk Grade**.

## Features
- **Proprietary Paywall Execution:** Integrates VirusTotal v3, GreyNoise Community, and AbuseIPDB via raw api keys, providing threat intelligence completely inaccessible to native LLM web searches.
- **Benign Scanner Filtering:** Cross-references active threats with GreyNoise to definitively tag "benign internet noise" (e.g., Google or Qualys scanners) to prevent false-positive agent panic.
- **In-Memory Federation Cache:** Implements an LRU caching engine dropping repeat query latencies to `0ms`, guaranteeing the sub-60s execution rule and protecting rigid upstream 60-req/min Key quotas.
- **Completeness Evaluator:** Employs the `searchExhausted` boolean natively to explicitly stop AI hallucination and retry loops when a true negative is found.
- **Builder Template Compliant:** Exposes exact Context Protocol Discovery tools (`get_all_threat_types`, `browse_by_threat_type`).

### Installation
1. Install dependencies:
   ```bash
   npm install
   ```
2. Copy the `.env.example` format and add your Keys:
   ```bash
   VIRUSTOTAL_API_KEY=your_key_here
   GREYNOISE_API_KEY=your_key_here
   ABUSEIPDB_API_KEY=your_key_here
   ```
3. Run the blazing-fast execution test to verify cache limits:
   ```bash
   npm run build
   npm test
   ```
