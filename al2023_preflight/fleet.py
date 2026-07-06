"""Fleet aggregation: read many report.json files, produce a fleet report.

Input: a directory of {hostname}-report_{date}.json files (schema v1),
collected locally, via scp, or downloaded from S3.
Output: grade distribution, top-blocker frequency, wave suggestions.
"""
import glob
import json
import os
from collections import Counter, defaultdict

GRADES = ["A", "B", "C", "D", "E"]

WAVE_RULES = [
    ("Wave 1 (now)", ("A", "B"),
     "ready or minor fixes — replatform immediately"),
    ("Wave 2 (after shared fixes)", ("C",),
     "unblocked once the shared blockers below are fixed"),
    ("Wave 3 (per-team)", ("D",),
     "file remediation tickets per owning team"),
    ("Project (separate)", ("E",),
     "effectively rebuilds — plan as individual projects"),
]


def load_reports(input_dir):
    """Load schema-v1 reports; keep only the newest per hostname."""
    latest = {}
    skipped = []
    for path in sorted(glob.glob(os.path.join(input_dir, "*.json"))):
        try:
            with open(path) as f:
                doc = json.load(f)
        except (IOError, ValueError) as e:
            skipped.append((path, "unreadable: %s" % e))
            continue
        if doc.get("schema_version") != 1:
            skipped.append((path, "unsupported schema_version=%r"
                            % doc.get("schema_version")))
            continue
        host = doc.get("hostname") or os.path.basename(path)
        prev = latest.get(host)
        if prev is None or doc.get("scanned_at", "") >= prev.get("scanned_at", ""):
            latest[host] = doc
    return list(latest.values()), skipped


def aggregate(reports):
    grade_hosts = defaultdict(list)
    blocker_hosts = defaultdict(set)
    finding_titles = {}
    for doc in reports:
        grade_hosts[doc["grade"]].append(doc["hostname"])
        for f in doc.get("findings", []):
            if "blocker" in f.get("flags", []):
                blocker_hosts[f["key"]].add(doc["hostname"])
                finding_titles.setdefault(f["key"], f["title"])
    top_blockers = sorted(blocker_hosts.items(),
                          key=lambda kv: (-len(kv[1]), kv[0]))
    return grade_hosts, top_blockers, finding_titles


def _bar(n, total, width=24):
    filled = int(round(width * n / total)) if total else 0
    return "#" * max(filled, 1 if n else 0)


def render_fleet_txt(reports, skipped, grade_hosts, top_blockers, titles):
    total = len(reports)
    W = 70
    lines = ["=" * W,
             " AL2 Fleet Migration Assessment — %d instances" % total,
             "=" * W, "",
             " Grade distribution"]
    for g in GRADES:
        hosts = grade_hosts.get(g, [])
        desc = {"A": "ready to replatform as-is", "B": "minor fixes",
                "C": "moderate work", "D": "significant preparation",
                "E": "effectively a rebuild"}[g]
        pct = (100 * len(hosts) // total) if total else 0
        lines.append("   %s %-24s %3d  (%2d%%)  %s"
                     % (g, _bar(len(hosts), total), len(hosts), pct, desc))
    lines += ["", " Top blockers (affected instances)"]
    if top_blockers:
        for i, (key, hosts) in enumerate(top_blockers[:10], 1):
            lines.append("   %d. %-38s %3d  %s"
                         % (i, key, len(hosts), titles.get(key, "")[:40]))
    else:
        lines.append("   none — no blockers across the fleet")
    lines += ["", " Suggested waves"]
    for name, grades, why in WAVE_RULES:
        hosts = [h for g in grades for h in grade_hosts.get(g, [])]
        if not hosts:
            continue
        lines.append("   %-28s %3d instances (grade %s) — %s"
                     % (name + ":", len(hosts), "/".join(grades), why))
        shown = ", ".join(sorted(hosts)[:6])
        more = "" if len(hosts) <= 6 else " (+%d more)" % (len(hosts) - 6)
        lines.append("     %s%s" % (shown, more))
    if skipped:
        lines += ["", " Skipped inputs (%d)" % len(skipped)]
        for path, why in skipped[:5]:
            lines.append("   %s — %s" % (os.path.basename(path), why))
    lines += ["", "-" * W,
              " Re-run scans after fixes and regenerate to track progress.",
              "-" * W, ""]
    return "\n".join(lines)


def run_fleet_report(input_dir, output_path=None, html_path=None):
    reports, skipped = load_reports(input_dir)
    if not reports:
        return None, "No schema-v1 reports found in %s" % input_dir
    grade_hosts, top_blockers, titles = aggregate(reports)
    text = render_fleet_txt(reports, skipped, grade_hosts, top_blockers, titles)
    if output_path:
        with open(output_path, "w") as f:
            f.write(text)
    if html_path:
        from .fleet_html import render_fleet_html
        generated_at = max(d.get("scanned_at", "") for d in reports)
        with open(html_path, "w") as f:
            f.write(render_fleet_html(reports, skipped, grade_hosts,
                                      top_blockers, titles, generated_at))
    return text, None
