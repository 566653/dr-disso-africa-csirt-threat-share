# DR Disso — CSIRT indicator exchange

**FR :** Privacy-preserving cyber threat indicator exchange. Prototype défensif libre et hors ligne pour les équipes autorisées des États africains, les CERT et les enquêteurs. **EN:** Privacy-preserving cyber threat indicator exchange. Free offline defensive prototype for authorized African public-sector teams, CSIRTs and investigators.

## Capabilities / Fonctionnalités
- Parse authorized local JSON events; deterministic severity triage; SHA-256 source integrity hash.
- No network connections, telemetry, personal-data harvesting or automatic enforcement.
- Synthetic example and unit tests; JSON output for audit.
- Adaptation to local regulations, privacy and human rights is required before deployment.

## Quick start / Démarrage
```bash
python engine.py examples/events.json --output findings.json
python -m unittest discover -s tests -v
```

## Scope / Limites
This is an **early prototype**, not a certified national platform, AI detector, or validated investigative conclusion. Severity rules are intentionally simple and need domain-specific tuning and evaluation. Do not feed personal or classified data without an approved governance process.

## Collaboration
Contributions welcome through GitHub issues and pull requests. MIT license.
