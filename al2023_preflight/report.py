"""Report rendering: report.json (machine-readable) and report.txt (human)."""
import json


GRADE_DESC = {
    "A": "ready to replatform as-is",
    "B": "minor fixes required",
    "C": "moderate preparation required",
    "D": "significant preparation required",
    "E": "effectively a rebuild",
}

SEV_LABEL = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}


def build_json(meta, findings, grade, score, effort):
    counts = {"blocker": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if f.blocker:
            counts["blocker"] += 1
        else:
            counts[f.severity] += 1
    return {
        # Schema v1 (docs/report-schema-v1.md) — the fleet aggregation pipeline
        # depends on this shape. Additive changes only; breaking changes bump the version.
        "schema_version": 1,
        "assessor_version": meta["version"],
        "data_version": meta["data_version"],
        "hostname": meta["hostname"],
        "instance_id": meta.get("instance_id"),
        "scanned_at": meta["scanned_at"],
        "grade": grade,
        "score": score,
        "estimated_effort": effort,
        "counts": counts,
        "top_blockers": [f.key for f in findings if f.blocker][:10],
        "findings": [f.to_dict() for f in findings],
    }


def render_txt(doc):
    W = 68
    lines = []
    bar = "=" * W
    lines += [bar,
              " AL2023 Migration Readiness Report",
              " hostname: %s   instance: %s" % (doc["hostname"], doc["instance_id"] or "n/a"),
              " scanned:  %s   preflight: v%s  data: %s"
              % (doc["scanned_at"], doc["assessor_version"], doc["data_version"]),
              bar, ""]
    for f in doc["findings"]:
        blocker = "blocker" in f["flags"]
        head = "[BLOCKER] (%s, effort: %s)" % (f["severity"], f["effort"]) if blocker \
            else "[%s] (effort: %s)" % (SEV_LABEL[f["severity"]], f["effort"])
        lines.append(head + " " + "-" * max(0, W - len(head) - 1))
        lines.append("Title:       %s" % f["title"])
        lines.append("Summary:     %s" % f["summary"])
        if f["remediation"]["hint"]:
            lines.append("Remediation: %s" % f["remediation"]["hint"])
        if f["related_resources"]:
            # group by scheme so the label appears once: "package: a, b, c"
            grouped = {}
            for r in f["related_resources"][:12]:
                grouped.setdefault(r["scheme"], []).append(r["id"])
            res = "; ".join("%s: %s" % (scheme, ", ".join(ids))
                            for scheme, ids in grouped.items())
            lines.append("Resources:   %s" % res)
        for url in f["remediation"]["links"][:2]:
            lines.append("Reference:   %s" % url)
        lines.append("key:         %s" % f["key"])
        lines.append("")
    c = doc["counts"]
    lines += ["-" * W,
              " Overall: grade %s | %d blockers | estimated effort: %s"
              % (doc["grade"], c["blocker"], doc["estimated_effort"]),
              " (%s)" % GRADE_DESC[doc["grade"]]]
    if c["blocker"]:
        lines.append(" Resolve all blockers before replatforming, or expect service")
        lines.append(" startup failures on the new AL2023 instance.")
    lines += [" NOTE: This report covers known breaking patterns only. Application-",
              " level incompatibilities require validation in a test environment.",
              "-" * W, ""]
    return "\n".join(lines)


def render_summary_box(doc):
    c = doc["counts"]
    W = 62
    return "\n".join([
        "=" * W,
        "  Overall grade:    %s  (%s)" % (doc["grade"], GRADE_DESC[doc["grade"]]),
        "  Findings:         %d blockers, %d high, %d medium, %d low, %d info"
        % (c["blocker"], c["high"], c["medium"], c["low"], c["info"]),
        "  Estimated effort: %s" % doc["estimated_effort"],
        "=" * W,
    ])


def write_reports(outdir, doc, formats=("txt",)):
    """Write reports named {hostname}-report_{date}.{ext}.

    txt is the default; pass formats including "json"/"html" to emit those
    too (json is required for fleet aggregation).
    """
    import os
    os.makedirs(outdir, exist_ok=True)
    date = doc["scanned_at"].split("T")[0]
    base = os.path.join(outdir, "%s-report_%s" % (doc["hostname"], date))
    written = []
    if "txt" in formats:
        path = base + ".txt"
        with open(path, "w") as f:
            f.write(render_txt(doc))
        written.append(path)
    if "json" in formats:
        path = base + ".json"
        with open(path, "w") as f:
            json.dump(doc, f, indent=2, ensure_ascii=False)
        written.append(path)
    if "html" in formats:
        from .report_html import render_html
        path = base + ".html"
        with open(path, "w") as f:
            f.write(render_html(doc))
        written.append(path)
    return written
