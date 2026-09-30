# Third-party notices

skill-scanner has no runtime dependencies. This file credits work it adapts, and lists the external tools it can invoke.

## Adapted material

### Cisco AI Defense skill-scanner (Apache License 2.0)

https://github.com/cisco-ai-defense/skill-scanner
Copyright 2026 Cisco Systems, Inc. and its affiliates

The jev probe questions and their shared instructions in `src/judge/probes.ts` are adapted from `evals/experiments/c3_openjev_local.py` (`THREAT_PROBES` and `INSTRUCTIONS`). Changes: each question is sent as a TypeSafe System One `choice` question with true/false criteria written for skill-scanner. The decision to ask `choice` rather than `noul` questions follows Cisco's published measurements in `docs/reference/measured-results.md`.

Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0). No Cisco code is included.

### gitleaks (MIT License)

https://github.com/gitleaks/gitleaks
Copyright (c) 2019 Zachary Rice

The shapes of several credential patterns in `src/core/secrets.ts` (token prefixes and lengths published by the issuers) were checked against gitleaks' default configuration. The patterns are written independently; no gitleaks rule file is included.

## Tools skill-scanner can invoke

These are never bundled. When you install one and enable it (`--with <name>` or `analyzers` in the config), skill-scanner runs it as a separate program and reads its output.

| Tool | License | Notes |
|---|---|---|
| NVIDIA SkillSpector | Apache-2.0 | run with `--no-llm`, OSV lookups disabled |
| Cisco AI Defense skill-scanner | Apache-2.0 | core offline analyzers only |
| gitleaks | MIT | pinned default configuration |
| osv-scanner | Apache-2.0 | queries osv.dev |
| semgrep / opengrep | LGPL-2.1 (engine) | registry rulesets are under the Semgrep Rules License and are fetched by semgrep, never redistributed |

## Research that shaped the rules

Detection ideas, not code, come from public research: Trail of Bits on skill distribution and scanner bypasses, Snyk's ToxicSkills study, Koi Security and Trend Micro on the ClawHavoc campaign, Embrace The Red on Unicode tag smuggling, Paul Butler on variation-selector smuggling, the Trojan Source paper (CVE-2021-42574), Check Point on Claude Code project-file execution (CVE-2025-59536), and the OWASP Top 10 for Agentic Applications.
