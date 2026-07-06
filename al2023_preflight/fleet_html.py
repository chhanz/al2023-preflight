"""Fleet HTML dashboard: single-file, no external assets (share-friendly)."""
try:
    from html import escape
except ImportError:
    from cgi import escape

from .fleet import GRADES, WAVE_RULES
from .report import GRADE_DESC

_GRADE_COLORS = {"A": "#1a7f37", "B": "#4d8f2f", "C": "#b58105",
                 "D": "#c4570b", "E": "#c62828"}

_CSS = """
body{font-family:-apple-system,'Segoe UI',Roboto,sans-serif;margin:0;
     background:#f5f6f8;color:#1c2733}
.wrap{max-width:1080px;margin:0 auto;padding:24px}
header{background:#141f2e;color:#fff;padding:20px 24px;border-radius:8px}
header h1{margin:0 0 6px;font-size:20px}
header .meta{font-size:13px;opacity:.8}
h2{font-size:16px;margin:28px 0 12px;color:#141f2e}
.cards{display:flex;gap:16px;flex-wrap:wrap;margin:20px 0}
.card{background:#fff;border-radius:8px;padding:16px 20px;flex:1;
      min-width:150px;box-shadow:0 1px 3px rgba(0,0,0,.08);text-align:center}
.card .label{font-size:12px;text-transform:uppercase;color:#68778a}
.card .value{font-size:30px;font-weight:700;margin-top:4px}
.gradebar{display:flex;height:34px;border-radius:6px;overflow:hidden;
          margin:8px 0 4px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.gradebar div{color:#fff;font-weight:700;font-size:13px;display:flex;
              align-items:center;justify-content:center;min-width:0}
.legend{font-size:12.5px;color:#455a64;margin-bottom:8px}
.legend b{display:inline-block;width:11px;height:11px;border-radius:2px;
          margin:0 4px 0 12px;vertical-align:-1px}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;
      box-shadow:0 1px 3px rgba(0,0,0,.08);overflow:hidden;font-size:13.5px}
th{background:#eef1f5;text-align:left;padding:9px 14px;color:#455a64;
   font-size:12px;text-transform:uppercase}
td{padding:9px 14px;border-top:1px solid #eef1f5;vertical-align:top}
.count-cell{font-weight:700;text-align:right;width:70px}
.hbar{background:#c62828;height:12px;border-radius:3px;display:inline-block;
      vertical-align:middle;margin-right:8px}
.grade-chip{display:inline-block;color:#fff;border-radius:4px;font-weight:700;
            padding:1px 9px;font-size:12px}
.hosts{font-family:monospace;font-size:12px;color:#455a64;word-break:break-all}
footer{font-size:12px;color:#68778a;margin:24px 0;line-height:1.6}
"""


def _grade_chip(g):
    return ('<span class="grade-chip" style="background:%s">%s</span>'
            % (_GRADE_COLORS[g], g))


def render_fleet_html(reports, skipped, grade_hosts, top_blockers, titles,
                      generated_at):
    total = len(reports)
    blockers_total = sum(d["counts"].get("blocker", 0) for d in reports)
    ready = len(grade_hosts.get("A", [])) + len(grade_hosts.get("B", []))

    # stacked grade bar (segment width proportional to share)
    segs, legend = [], []
    for g in GRADES:
        n = len(grade_hosts.get(g, []))
        legend.append('<b style="background:%s"></b>%s %s (%d)'
                      % (_GRADE_COLORS[g], g, GRADE_DESC[g], n))
        if n:
            pct = 100.0 * n / total
            segs.append('<div style="background:%s;width:%.1f%%" '
                        'title="%s: %d">%s:%d</div>'
                        % (_GRADE_COLORS[g], pct, GRADE_DESC[g], n, g, n))
    gradebar = ('<div class="gradebar">%s</div><div class="legend">%s</div>'
                % ("".join(segs), "".join(legend)))

    # top blockers table
    max_n = max((len(h) for _k, h in top_blockers), default=1)
    rows = []
    for key, hosts in top_blockers[:10]:
        w = int(160 * len(hosts) / max_n)
        rows.append(
            "<tr><td><code>%s</code><br><span style='color:#68778a'>%s</span></td>"
            "<td class='count-cell'><span class='hbar' style='width:%dpx'></span>%d</td>"
            "<td class='hosts'>%s</td></tr>"
            % (escape(key), escape(titles.get(key, "")[:90]), w, len(hosts),
               escape(", ".join(sorted(hosts)[:4]) +
                      ("" if len(hosts) <= 4 else " +%d" % (len(hosts) - 4)))))
    blocker_table = (
        "<table><tr><th>Blocker (finding key)</th><th>Hosts</th>"
        "<th>Affected</th></tr>%s</table>" % "".join(rows)
        if rows else "<p>No blockers across the fleet.</p>")

    # waves table
    wave_rows = []
    for name, grades, why in WAVE_RULES:
        hosts = sorted(h for g in grades for h in grade_hosts.get(g, []))
        if not hosts:
            continue
        wave_rows.append(
            "<tr><td><b>%s</b><br><span style='color:#68778a'>%s</span></td>"
            "<td>%s</td><td class='count-cell'>%d</td><td class='hosts'>%s</td></tr>"
            % (escape(name), escape(why),
               " ".join(_grade_chip(g) for g in grades if grade_hosts.get(g)),
               len(hosts),
               escape(", ".join(hosts[:6]) +
                      ("" if len(hosts) <= 6 else " +%d more" % (len(hosts) - 6)))))
    wave_table = ("<table><tr><th>Wave</th><th>Grades</th><th>Hosts</th>"
                  "<th>Instances</th></tr>%s</table>" % "".join(wave_rows))

    # per-instance table
    inst_rows = []
    for doc in sorted(reports, key=lambda d: (GRADES.index(d["grade"]),
                                              d["hostname"])):
        c = doc["counts"]
        tb = ", ".join(doc.get("top_blockers", [])[:3]) or "—"
        inst_rows.append(
            "<tr><td class='hosts'>%s</td><td>%s</td>"
            "<td class='count-cell'>%d</td><td>%s</td><td>%s</td></tr>"
            % (escape(doc["hostname"]), _grade_chip(doc["grade"]),
               c.get("blocker", 0), escape(doc.get("estimated_effort", "")),
               escape(tb)))
    inst_table = ("<table><tr><th>Hostname</th><th>Grade</th><th>Blockers</th>"
                  "<th>Effort</th><th>Top blockers</th></tr>%s</table>"
                  % "".join(inst_rows))

    skipped_html = ""
    if skipped:
        items = "".join("<li><code>%s</code> — %s</li>"
                        % (escape(p.split('/')[-1]), escape(w))
                        for p, w in skipped[:5])
        skipped_html = "<h2>Skipped inputs (%d)</h2><ul>%s</ul>" % (
            len(skipped), items)

    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>AL2 Fleet Migration Assessment — %d instances</title>
<style>%s</style></head><body><div class="wrap">
<header><h1>AL2 Fleet Migration Assessment</h1>
<div class="meta">%d instances &nbsp;·&nbsp; generated %s &nbsp;·&nbsp;
newest report per hostname</div></header>
<div class="cards">
<div class="card"><div class="label">Instances</div><div class="value">%d</div></div>
<div class="card"><div class="label">Ready now (A/B)</div>
  <div class="value" style="color:#1a7f37">%d</div></div>
<div class="card"><div class="label">Total blockers</div>
  <div class="value" style="color:#c62828">%d</div></div>
<div class="card"><div class="label">Rebuilds (E)</div><div class="value">%d</div></div>
</div>
<h2>Grade distribution</h2>%s
<h2>Top blockers</h2>%s
<h2>Suggested waves</h2>%s
<h2>Instances</h2>%s
%s
<footer>Grades: A (ready as-is) &rarr; E (effectively a rebuild).
Re-run fleet scans after fixes and regenerate this dashboard to track
progress. Report schema v1.</footer>
</div></body></html>""" % (
        total, _CSS, total, escape(generated_at), total, ready,
        blockers_total, len(grade_hosts.get("E", [])), gradebar,
        blocker_table, wave_table, inst_table, skipped_html)
