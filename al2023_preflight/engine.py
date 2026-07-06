"""Core engine: in-memory message bus, check registry, phase runner.

Design borrowed from leapp (Facts -> Checks -> Score -> Report phase
discipline, produces/consumes declarations, error isolation) but reduced
to an in-memory, single-run, read-only assessment engine.

Python 3.7 compatible (AL2 system python3), stdlib only.
"""
import logging
import traceback
from collections import defaultdict

log = logging.getLogger("al2023-preflight")

# severity ordering: used for sorting findings in reports
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
EFFORT_WEIGHT = {"trivial": 1, "small": 2, "medium": 4, "large": 8, "rebuild": 16}
SEVERITY_WEIGHT = {"info": 0, "low": 1, "medium": 3, "high": 6}
BLOCKER_BONUS = 10


class Finding(object):
    """A single assessment finding (leapp Report entry, replatform semantics)."""

    def __init__(self, key, title, summary, severity="medium", effort="small",
                 blocker=False, groups=None, remediation=None, links=None,
                 related_resources=None):
        assert severity in SEVERITY_WEIGHT, "invalid severity: %s" % severity
        assert effort in EFFORT_WEIGHT, "invalid effort: %s" % effort
        self.key = key
        self.title = title
        self.summary = summary
        self.severity = severity
        self.effort = effort
        self.blocker = blocker
        self.groups = groups or []
        self.remediation = remediation or ""
        self.links = links or []
        self.related_resources = related_resources or []  # list of (scheme, id)

    @property
    def score(self):
        s = SEVERITY_WEIGHT[self.severity] * EFFORT_WEIGHT[self.effort]
        if self.blocker:
            s += BLOCKER_BONUS
        return s

    def to_dict(self):
        return {
            "key": self.key,
            "title": self.title,
            "summary": self.summary,
            "severity": self.severity,
            "flags": ["blocker"] if self.blocker else [],
            "groups": self.groups,
            "effort": self.effort,
            "remediation": {"hint": self.remediation, "links": self.links},
            "related_resources": [
                {"scheme": s, "id": i} for (s, i) in self.related_resources
            ],
        }


class Bus(object):
    """In-memory message bus: fact-model name -> list of payload dicts."""

    def __init__(self):
        self._messages = defaultdict(list)

    def produce(self, model_name, payload):
        self._messages[model_name].append(payload)

    def consume(self, model_name):
        return list(self._messages.get(model_name, []))

    def consume_one(self, model_name, default=None):
        msgs = self._messages.get(model_name)
        return msgs[0] if msgs else default


class Registry(object):
    """Holds registered scanners (facts phase) and checks (checks phase)."""

    def __init__(self):
        self.scanners = []   # list of (name, func(bus, ctx))
        self.checks = []     # list of (name, func(bus, ctx) -> [Finding])

    def scanner(self, name):
        def deco(fn):
            self.scanners.append((name, fn))
            return fn
        return deco

    def check(self, name):
        def deco(fn):
            self.checks.append((name, fn))
            return fn
        return deco


registry = Registry()


def compute_grade(findings):
    """Instance-level grade (A best .. E worst) from the finding scores."""
    total = sum(f.score for f in findings)
    blockers = sum(1 for f in findings if f.blocker)
    if blockers == 0 and total <= 5:
        grade = "A"
    elif blockers == 0 and total <= 20:
        grade = "B"
    elif blockers <= 1 and total <= 60:
        grade = "C"
    elif total <= 140:
        grade = "D"
    else:
        grade = "E"
    effort = {"A": "days", "B": "days", "C": "weeks", "D": "weeks", "E": "months"}[grade]
    return grade, total, effort


def run_assessment(ctx, progress=None):
    """Execute Facts -> Checks -> Score. Returns (findings, grade, score, effort, stats).

    Errors in an individual scanner/check are isolated (leapp FailPhase
    policy): logged, counted, and the run continues.
    """
    bus = Bus()
    stats = {"scanners_ok": 0, "scanners_failed": 0,
             "checks_ok": 0, "checks_failed": 0, "check_errors": {}}

    def emit(msg):
        if progress:
            progress(msg)

    emit("[1/4] Collecting facts...")
    for name, fn in registry.scanners:
        try:
            summary = fn(bus, ctx)
            stats["scanners_ok"] += 1
            emit("  OK  %-18s %s" % (name, summary or ""))
        except Exception:
            stats["scanners_failed"] += 1
            log.error("scanner %s failed:\n%s", name, traceback.format_exc())
            emit("  FAIL %-17s (isolated, see log)" % name)

    emit("[2/4] Running checks...")
    findings = []
    for name, fn in registry.checks:
        try:
            result = fn(bus, ctx) or []
            findings.extend(result)
            stats["checks_ok"] += 1
        except Exception:
            stats["checks_failed"] += 1
            stats["check_errors"][name] = traceback.format_exc()
            log.error("check %s failed:\n%s", name, stats["check_errors"][name])
    emit("      %d checks executed (%d failed)"
         % (stats["checks_ok"] + stats["checks_failed"], stats["checks_failed"]))

    emit("[3/4] Scoring...")
    findings.sort(key=lambda f: (not f.blocker, SEVERITY_ORDER[f.severity], -f.score))
    grade, score, effort = compute_grade(findings)
    return findings, grade, score, effort, stats
