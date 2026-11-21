# Roadmap and comparative design notes / Feuille de route

This is a **defensive, offline, rule-based prototype**, not a production platform. No claim of 90% completion or detection accuracy is made.

## Improvements in this update
- Explainable matched-rule evidence and per-severity summary
- More precise token matching (reduces accidental substring matches)
- Bounded local input size and event count; stricter field validation
- Regression tests and deterministic SHA-256 input fingerprint
- Offline operation; no automatic surveillance, attribution, blocking or external calls

## Design references (ideas, not copied code)
- DFIR-IRIS: https://www.dfir-iris.org/features/ — case workflows, evidence provenance and audit trails
- MISP: https://github.com/MISP/MISP — structured indicators, sharing and data standards
- OpenCTI: https://github.com/OpenCTI-Platform/opencti — provenance and confidence
- Prowler: https://github.com/prowler-cloud/prowler — extensible checks and evidence-based reporting

## Next milestones toward a production-readiness review
1. Threat model and requirements for each specific domain
2. Authenticated API, RBAC and immutable audit trail (if server deployment is authorized)
3. Configurable rules with documented false-positive/false-negative evaluation
4. Structured interoperability formats with schema validation
5. Reproducible packaging, dependency/SBOM and release signing
6. Privacy, retention, access controls, accessibility and bilingual documentation
7. Independent security review and field acceptance tests

**Important:** these are future milestones, not implemented capabilities. No source code was copied from the referenced projects.
