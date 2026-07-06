# report.json schema v1

The fleet aggregation pipeline (`fleet-report`) consumes this document.
Additive changes are allowed; renaming/removing fields or changing types
requires bumping `schema_version`.

```jsonc
{
  "schema_version": 1,          // int — this document
  "assessor_version": "0.1.0",  // tool version that produced the report
  "data_version": "2026-07-03", // knowledge-data snapshot date
  "hostname": "web-01",         // socket.gethostname()
  "instance_id": "i-0abc...",   // EC2 instance id via IMDSv2, null off-EC2
  "scanned_at": "2026-07-06T01:47:22Z",  // UTC, ISO-8601
  "grade": "D",                 // A|B|C|D|E (A best, E worst)
  "score": 71,                  // int, sum of finding scores
  "estimated_effort": "weeks",  // days|weeks|months
  "counts": {                   // a finding counts toward exactly ONE bucket:
    "blocker": 2,               //   blocker if flagged, else its severity
    "high": 0, "medium": 3, "low": 2, "info": 1
  },
  "top_blockers": ["epel-packages-in-use", "..."],  // finding keys, max 10
  "findings": [
    {
      "key": "epel-packages-in-use",   // STABLE id — fleet aggregation axis
      "title": "...",                  // one-line English title
      "summary": "...",                // details, English
      "severity": "high",              // info|low|medium|high
      "flags": ["blocker"],            // [] or ["blocker"]
      "groups": ["repository"],        // category labels
      "effort": "large",               // trivial|small|medium|large|rebuild
      "remediation": {
        "hint": "...",                 // may be ""
        "links": ["https://..."]       // may be []
      },
      "related_resources": [
        {"scheme": "package", "id": "fail2ban"}
        // schemes: package | file | process | extras-topic | kernel-module
      ]
    }
  ]
}
```

Invariants the aggregator may rely on:

- `key` is stable across runs and hosts for the same root cause.
- `grade` ∈ {A..E}; `counts` keys are exactly the five above.
- A finding is EITHER a blocker OR counted under its severity, never both.
- File naming: `{hostname}-report_{YYYY-MM-DD}.json`.
