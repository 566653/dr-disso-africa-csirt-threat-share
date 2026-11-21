# Architecture / Architecture

1. Input: locally provided UTF-8 JSON list of approved events.
2. Validation: reject non-list payloads and non-object records.
3. Rules: deterministic severity matching; no AI or remote inference.
4. Integrity: SHA-256 digest of exact input bytes.
5. Output: JSON findings and human-review warning.
6. Boundaries: no automatic blocking, network traffic, or third-party data collection.

## Roadmap
- Project-specific event schemas and realistic synthetic test corpora.
- Precision/recall, false-positive and latency benchmarks.
- Threat modeling, privacy impact assessment and independent code review.
- Optional signed evidence manifests and local access controls.
