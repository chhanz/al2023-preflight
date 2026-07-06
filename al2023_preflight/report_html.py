"""Single-file HTML report renderer (no external assets, share-friendly)."""
try:
    from html import escape
except ImportError:  # py2 fallback, not expected in practice
    from cgi import escape

from .report import GRADE_DESC

_GRADE_COLORS = {"A": "#1a7f37", "B": "#4d8f2f", "C": "#b58105",
                 "D": "#c4570b", "E": "#c62828"}
_SEV_COLORS = {"high": "#c62828", "medium": "#b58105",
               "low": "#4d8f2f", "info": "#546e7a"}

_CSS = """
body{font-family:-apple-system,'Segoe UI',Roboto,sans-serif;margin:0;
     background:#f5f6f8;color:#1c2733}
.wrap{max-width:960px;margin:0 auto;padding:24px}
header{background:#141f2e;color:#fff;padding:20px 24px;border-radius:8px}
header h1{margin:0 0 6px;font-size:20px}
header .meta{font-size:13px;opacity:.8}
.summary{display:flex;gap:16px;margin:20px 0;flex-wrap:wrap}
.card{background:#fff;border-radius:8px;padding:16px 20px;
      box-shadow:0 1px 3px rgba(0,0,0,.08);flex:1;min-width:180px}
.card .label{font-size:12px;text-transform:uppercase;color:#68778a}
.card .value{font-size:26px;font-weight:700;margin-top:4px}
.grade-badge{display:inline-block;color:#fff;border-radius:6px;
             padding:2px 14px;font-size:26px;font-weight:700}
.finding{background:#fff;border-radius:8px;margin:12px 0;padding:16px 20px;
         box-shadow:0 1px 3px rgba(0,0,0,.08);border-left:5px solid #ccc}
.finding h3{margin:0 0 8px;font-size:15px}
.tag{display:inline-block;font-size:11px;font-weight:700;border-radius:4px;
     padding:1px 8px;margin-right:6px;color:#fff;vertical-align:2px}
.blocker-tag{background:#c62828}
.finding p{margin:6px 0;font-size:13.5px;line-height:1.55}
.finding .label{font-weight:600;color:#455a64}
.finding .key{font-size:11px;color:#8a99a8;font-family:monospace}
.res{font-size:12.5px;color:#455a64;font-family:monospace;word-break:break-all}
footer{font-size:12px;color:#68778a;margin:24px 0;line-height:1.6}
a{color:#0b5cad}
"""


def _finding_html(f):
    blocker = "blocker" in f["flags"]
    sev_color = _SEV_COLORS.get(f["severity"], "#ccc")
    border = "#c62828" if blocker else sev_color
    tags = ""
    if blocker:
        tags += '<span class="tag blocker-tag">BLOCKER</span>'
    tags += ('<span class="tag" style="background:%s">%s</span>'
             % (sev_color, f["severity"].upper()))
    tags += ('<span class="tag" style="background:#68778a">effort: %s</span>'
             % f["effort"])
    parts = ['<div class="finding" style="border-left-color:%s">' % border,
             "<h3>%s %s</h3>" % (tags, escape(f["title"])),
             '<p>%s</p>' % escape(f["summary"])]
    if f["remediation"]["hint"]:
        parts.append('<p><span class="label">Remediation:</span> %s</p>'
                     % escape(f["remediation"]["hint"]))
    if f["related_resources"]:
        grouped = {}
        for r in f["related_resources"][:12]:
            grouped.setdefault(r["scheme"], []).append(r["id"])
        res = "; ".join("%s: %s" % (s, ", ".join(ids))
                        for s, ids in grouped.items())
        parts.append('<p class="res">%s</p>' % escape(res))
    for url in f["remediation"]["links"][:2]:
        parts.append('<p><a href="%s">%s</a></p>' % (escape(url), escape(url)))
    parts.append('<span class="key">key: %s</span></div>' % escape(f["key"]))
    return "\n".join(parts)


def render_html(doc):
    c = doc["counts"]
    grade = doc["grade"]
    cards = """
    <div class="card"><div class="label">Overall grade</div>
      <div class="value"><span class="grade-badge" style="background:%s">%s</span></div>
      <div style="font-size:12.5px;color:#68778a;margin-top:6px">%s</div></div>
    <div class="card"><div class="label">Blockers</div><div class="value">%d</div></div>
    <div class="card"><div class="label">Findings</div>
      <div class="value">%d</div>
      <div style="font-size:12.5px;color:#68778a">%d high / %d medium / %d low / %d info</div></div>
    <div class="card"><div class="label">Estimated effort</div><div class="value">%s</div></div>
    """ % (_GRADE_COLORS[grade], grade, GRADE_DESC[grade], c["blocker"],
           len(doc["findings"]), c["high"], c["medium"], c["low"], c["info"],
           doc["estimated_effort"])

    findings_html = "\n".join(_finding_html(f) for f in doc["findings"])
    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>AL2023 Migration Readiness — %s</title>
<style>%s</style></head><body><div class="wrap">
<header><h1>AL2023 Migration Readiness Report</h1>
<div class="meta">hostname: %s &nbsp;·&nbsp; instance: %s &nbsp;·&nbsp;
scanned: %s &nbsp;·&nbsp; preflight v%s &nbsp;·&nbsp; data: %s</div></header>
<div class="summary">%s</div>
%s
<footer>NOTE: This report covers known breaking patterns only.
Application-level incompatibilities require validation in a test
environment. Grades: A (ready as-is) &rarr; E (effectively a rebuild).</footer>
</div></body></html>""" % (
        escape(doc["hostname"]), _CSS, escape(doc["hostname"]),
        escape(doc["instance_id"] or "n/a"), escape(doc["scanned_at"]),
        escape(doc["assessor_version"]), escape(doc["data_version"]),
        cards, findings_html)
