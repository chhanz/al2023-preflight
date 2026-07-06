"""CLI entry point: al2023-preflight scan [--output DIR] [--json-only]"""
import argparse
import datetime
import json
import logging
import os
import socket
import sys

from . import __version__
from .engine import run_assessment
from . import facts   # noqa: F401  (registers scanners)
from . import checks  # noqa: F401  (registers checks)
from .report import build_json, write_reports, render_summary_box


def load_data():
    base = os.path.join(os.path.dirname(__file__), "data")
    with open(os.path.join(base, "knowledge.json")) as f:
        data = json.load(f)
    # package-existence DBs (one name per line), generated via:
    #   dnf repoquery --repo amazonlinux --qf '%{name}' | sort -u
    #   dnf repoquery --repo amazonlinux-spal --qf '%{name}' | sort -u
    for key, fname in (("al2023_core_packages", "al2023-core-packages.txt"),
                       ("spal_packages", "spal-packages.txt")):
        path = os.path.join(base, fname)
        if os.path.exists(path):
            with open(path) as f:
                # '#'-prefixed header lines carry generation date/source
                data[key] = set(l.strip() for l in f
                                if l.strip() and not l.startswith("#"))
        else:
            data[key] = set()
    return data


def get_instance_id():
    """Best-effort instance id via IMDSv2 (read-only; None off-EC2)."""
    try:
        import urllib.request
        req = urllib.request.Request(
            "http://169.254.169.254/latest/api/token", method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"})
        token = urllib.request.urlopen(req, timeout=2).read().decode()
        req = urllib.request.Request(
            "http://169.254.169.254/latest/meta-data/instance-id",
            headers={"X-aws-ec2-metadata-token": token})
        return urllib.request.urlopen(req, timeout=2).read().decode()
    except Exception:
        return None


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="al2023-preflight",
        description="AL2 to AL2023 replatform readiness assessment (read-only)")
    sub = parser.add_subparsers(dest="command")
    scan = sub.add_parser("scan", help="scan this instance and write a report")
    scan.add_argument("--output", default="/var/tmp/al2023-preflight",
                      help="output directory (default: /var/tmp/al2023-preflight)")
    scan.add_argument("--json", action="store_true",
                      help="also write a JSON report (fleet aggregation input)")
    scan.add_argument("--html", action="store_true",
                      help="also write a single-file HTML report")
    scan.add_argument("--force", action="store_true",
                      help="scan even if this host is not Amazon Linux 2")
    scan.add_argument("--verbose", action="store_true")
    fleet = sub.add_parser("fleet-report",
                           help="aggregate collected report.json files")
    fleet.add_argument("--input", required=True,
                       help="directory containing *-report_*.json files")
    fleet.add_argument("--output", default=None,
                       help="also write the fleet report to this file")
    fleet.add_argument("--html", default=None, metavar="PATH",
                       help="also write a single-file HTML dashboard")
    args = parser.parse_args(argv)

    if args.command == "fleet-report":
        from .fleet import run_fleet_report
        text, err = run_fleet_report(args.input, args.output, args.html)
        if err:
            print("ERROR: %s" % err)
            return 3
        print(text)
        for path in (args.output, args.html):
            if path:
                print("Written: %s" % path)
        return 0

    if args.command != "scan":
        parser.print_help()
        return 2

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s")

    print("al2023-preflight v%s — AL2 to AL2023 replatform readiness "
          "assessment (read-only)\n" % __version__)

    # source-OS guard: checks are written for AL2; other distros produce noise
    try:
        with open("/etc/system-release") as f:
            release = f.read().strip()
    except IOError:
        release = ""
    import re
    if not re.search(r"Amazon Linux release 2\b(?!\d)", release):
        msg = ("This host is not Amazon Linux 2 (found: %s)."
               % (release or "no /etc/system-release"))
        if not args.force:
            print("ERROR: %s\nChecks are calibrated for AL2 sources; results "
                  "elsewhere are unreliable. Use --force to scan anyway." % msg)
            return 3
        print("WARNING: %s Proceeding due to --force; expect noisy results.\n" % msg)

    if os.geteuid() != 0:
        print("WARNING: not running as root — some facts (user crontabs, "
              "protected configs) will be incomplete.\n")

    data = load_data()
    ctx = {"data": data}
    findings, grade, score, effort, stats = run_assessment(ctx, progress=print)

    formats = ["txt"]
    if args.json:
        formats.append("json")
    if args.html:
        formats.append("html")
    print("[4/4] Writing report -> %s (%s)\n" % (args.output, ", ".join(formats)))
    meta = {
        "version": __version__,
        "data_version": data.get("data_version", "unknown"),
        "hostname": socket.gethostname(),
        "instance_id": get_instance_id(),
        "scanned_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    doc = build_json(meta, findings, grade, score, effort)
    written = write_reports(args.output, doc, formats=formats)

    print(render_summary_box(doc))
    for path in written:
        print("Report: %s" % path)
    if stats["checks_failed"]:
        print("NOTE: %d checks failed and were skipped (run with --verbose)."
              % stats["checks_failed"])
    # exit code: 0 clean, 1 findings exist, 2 blockers exist (CI-friendly)
    if doc["counts"]["blocker"]:
        return 2
    return 1 if doc["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
