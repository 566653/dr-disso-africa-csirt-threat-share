"""Offline defensive event triage with explainable, deterministic rules."""
import argparse
import hashlib
import json
import pathlib
import re
from collections import Counter

RULES = {
    "critical": ("unauthorized", "ransomware", "exfiltration", "tamper", "compromised", "disabled_backup"),
    "high": ("suspicious", "unexpected", "privilege", "failed_login", "sim_swap", "fraud", "unpatched"),
    "medium": ("review", "outdated", "unknown", "configuration", "warning"),
}
MAX_EVENTS = 10000
MAX_BYTES = 5 * 1024 * 1024
MAX_FIELD_CHARS = 20000
FIELDS = ("event", "detail", "status")
SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "info": 0}


def _matched_rule(description):
    for severity, words in RULES.items():
        for word in words:
            # Match whole tokens; underscores and hyphens are treated as separators.
            pattern = r"(?<![a-z0-9])" + re.escape(word).replace("_", r"[_ -]") + r"(?![a-z0-9])"
            if re.search(pattern, description):
                return severity, word
    return "info", None


def assess(records):
    if not isinstance(records, list):
        raise ValueError("Expected a JSON list of events")
    if len(records) > MAX_EVENTS:
        raise ValueError("Too many events")
    findings = []
    for index, item in enumerate(records):
        if not isinstance(item, dict):
            raise ValueError("Every event must be a JSON object")
        for field in FIELDS:
            if field in item and not isinstance(item[field], (str, int, float, bool, type(None))):
                raise ValueError("Event text fields must be scalar")
            if len(str(item.get(field, ""))) > MAX_FIELD_CHARS:
                raise ValueError("Event text field too long")
        description = " ".join(str(item.get(k, "")) for k in FIELDS).lower()
        severity, rule = _matched_rule(description)
        findings.append({
            "index": index,
            "event_id": str(item.get("id", index)),
            "severity": severity,
            "matched_rule": rule,
            "reason": "Matched documented keyword rule; analyst validation required" if rule else "No documented keyword rule matched; analyst validation required",
        })
    return findings


def run(input_path):
    raw = pathlib.Path(input_path).read_bytes()
    if len(raw) > MAX_BYTES:
        raise ValueError("Input exceeds 5 MiB")
    records = json.loads(raw.decode("utf-8"))
    findings = assess(records)
    counts = Counter(f["severity"] for f in findings)
    return {
        "project": pathlib.Path(__file__).parent.name,
        "schema_version": "1.1",
        "input_sha256": hashlib.sha256(raw).hexdigest(),
        "count": len(findings),
        "severity_counts": {k: counts[k] for k in SEVERITY_RANK},
        "findings": findings,
        "notice": "Demonstration triage only; no attribution or enforcement; analyst validation required.",
    }


def main():
    parser = argparse.ArgumentParser(description="Offline defensive event triage")
    parser.add_argument("input", help="Local JSON array of events")
    parser.add_argument("--output", help="Output JSON file")
    args = parser.parse_args()
    result = json.dumps(run(args.input), indent=2, ensure_ascii=False)
    if args.output:
        pathlib.Path(args.output).write_text(result + "\n", encoding="utf-8")
    else:
        print(result)


if __name__ == "__main__":
    main()
