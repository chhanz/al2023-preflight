# al2023-preflight

Read-only pre-flight assessment for migrating Amazon Linux 2 workloads to
Amazon Linux 2023.

AL2 reached end of support on 2026-06-30, and there is no in-place upgrade
path to AL2023 — the supported route is redeploying onto new AL2023
instances. `al2023-preflight` scans an AL2 instance **without changing
anything** and reports what will break after the replatform: missing
packages, EPEL dependencies, IMDSv1 callers, OpenSSL 1.0.x-linked binaries,
cgroup v2 hazards, legacy TLS configuration, and more. Each finding comes
with a severity, an effort estimate, and a remediation hint, and every
instance receives an overall migration-difficulty grade (A–E) so fleets can
be scheduled in waves.

The assessment model is inspired by the pre-upgrade analysis of
[leapp](https://github.com/oamg/leapp) (RHEL's in-place upgrade tool),
reinterpreted for a redeploy-not-upgrade context.

## Requirements

- Amazon Linux 2 host (non-AL2 hosts are rejected; override with `--force`)
- Python 3.7+ (the AL2 system `python3`), standard library only — no
  dependencies
- Run as root for full fact collection (degrades gracefully without)

## Usage

```
$ sudo python3 -m al2023_preflight.cli scan
$ sudo python3 -m al2023_preflight.cli scan --json --html   # extra formats
```

Reports are written to `/var/tmp/al2023-preflight` (change with `--output`)
and named `{hostname}-report_{date}.{ext}`. By default only the
human-readable `.txt` is written; `--json` adds the machine-readable report
(fleet-aggregation input, schema v1 — see `docs/report-schema-v1.md`) and
`--html` adds a single-file HTML report.

Exit codes: `0` clean, `1` findings, `2` blockers present (CI-friendly).

## Fleet workflow

Assess many instances, aggregate centrally, and plan migration waves:

1. **Collect** — run a JSON scan on every AL2 host and gather the reports
   into one directory. Two channels:
   - **SSM** (recommended at scale): register `fleet/ssm-run-preflight.yaml`
     once, then
     `aws ssm send-command --document-name RunAL2023Preflight --targets Key=tag:<your-tag>,Values=<value> ...`
     — each host uploads its `{hostname}-report_{date}.json` to S3.
     The instance role needs `s3:GetObject` on the tool object and
     `s3:PutObject` on the report prefix (a bucket policy works well).
   - **SSH fallback**: `./fleet/collect-ssh.sh <outdir> <host1> <host2> ...`
2. **Aggregate**:
   ```
   $ python3 -m al2023_preflight.cli fleet-report --input <dir> \
       [--output fleet.txt] [--html dashboard.html]
   ```
   Produces the grade distribution, top-blocker frequency (keyed by stable
   finding `key`), and wave suggestions (Wave 1: A/B now, Wave 2: C after
   shared fixes, Wave 3: D per-team, Project: E rebuilds). `--html` writes
   a single-file dashboard for management sharing. Only the newest report
   per hostname is counted, so periodic re-scans naturally track progress.

## Grades

`A` (best) → `E` (worst). The grade summarizes how hard it is to replatform
the instance to AL2023.

| Grade | Meaning | Criteria (blockers / score) | Estimated effort |
|-------|---------|-----------------------------|------------------|
| A | ready to replatform as-is | 0 blockers, score <= 5 | days |
| B | minor fixes required | 0 blockers, score <= 20 | days |
| C | moderate preparation required | <= 1 blocker, score <= 60 | weeks |
| D | significant preparation required | score <= 140 | weeks |
| E | effectively a rebuild | score > 140 | months |

Scoring: each finding scores `severity_weight × effort_weight` (severity
info=0 / low=1 / medium=3 / high=6; effort trivial=1 / small=2 / medium=4 /
large=8 / rebuild=16), and a **blocker** flag adds +10. A blocker means the
workload will fail on the new instance unless resolved first — it is
orthogonal to severity, following leapp's inhibitor-as-flag design. The
instance score is the sum over all findings. Thresholds are heuristics
tuned on real instances; treat the grade as a planning signal, not a
guarantee.

## Implemented checks

epel-packages-in-use (triaged against AL2023 core and SPAL) ·
extras-topics-in-use · packages-missing-in-al2023 · python2-dependents
(shebang scan, `rpm --whatrequires` reverse lookup, live-process detection)
· imdsv1-callers · libssl10-linked-binaries · cgroupv2-unsafe-runtimes ·
cgroupv1-hardcoded-paths · userdata-bootstrap-breakage · i686-binaries ·
third-party-kernel-modules · ntp-to-chrony · rsyslog-remote-forwarding ·
awslogs-agent-removed · sendmail-removed · auth-chain-changes ·
network-scripts-customization · cron-jobs-present · tls-legacy-config ·
weak-signature-certs · awscli-v1-scripts · systemd-deprecated-directives ·
third-party-agents

## Layout

```
al2023_preflight/
├── engine.py         # message bus, check registry, Finding, grading
├── facts.py          # read-only scanners (facts phase)
├── checks.py         # judgement over facts (checks phase)
├── report.py         # txt/json rendering; report_html.py for HTML
├── fleet.py          # fleet aggregation; fleet_html.py for the dashboard
├── cli.py            # scan / fleet-report subcommands
└── data/
    ├── knowledge.json           # AL2→AL2023 knowledge (extras topics,
    │                            # removed pkgs, JVM cgroup-v2 minimums)
    ├── al2023-core-packages.txt # AL2023 core package-existence DB
    └── spal-packages.txt        # SPAL (EPEL9 rebuild) package-existence DB
docs/report-schema-v1.md         # frozen JSON report contract
fleet/                           # SSM document + SSH collector
scripts/refresh-package-db.sh    # regenerate the package DBs
tests/test_demo.py               # end-to-end test over synthetic facts
```

## Knowledge-data refresh

Check accuracy tracks the freshness of `al2023_preflight/data/`. To
refresh, run `scripts/refresh-package-db.sh` on an up-to-date AL2023 host
and commit the diff; each DB file carries a `# generated:` header
identifying its snapshot. A refresh pipeline aligned with the AL2023 AMI
release cycle (quarterly) is planned: regenerate on each release, review
the diff, and push the updated data to this repository so deployed copies
pick up current data without code changes.

## Test

```
$ python3 tests/test_demo.py
```

Feeds synthetic facts for a worst-case legacy host through every check and
asserts all expected findings fire.

## Limitations

- **Not an official Amazon Linux / AWS tool.** This is an independent,
  community project with no affiliation to, or endorsement by, Amazon Web
  Services. AWS provides no automated AL2-to-AL2023 assessment tool; this
  project fills that gap on a best-effort basis. Findings and remediation
  hints are not AWS guidance — always cross-check against the official
  [AL2023 documentation](https://docs.aws.amazon.com/linux/al2023/ug/).
- **No application-level migration assessment.** The scan stops at the OS
  layer: packages, repositories, linked libraries, system configuration,
  provisioning scripts, and running interpreters. It does not analyze your
  application source code, framework/library compatibility, database
  engine behavior, or runtime business logic (e.g. code calling OpenSSL 3
  removed APIs, or an app depending on version-specific behavior of a
  package that AL2023 ships in a newer major version). A clean grade means
  the OS-level replatform surface looks manageable — it does not certify
  that the application will work. Always validate workloads on a real
  AL2023 test instance before cutover.
- Grades are planning signals calibrated on a limited instance sample.
- SPAL-covered packages are provided as-is from upstream EPEL9, are not
  covered by AWS Support Plans, and receive no AWS CVE tracking — review
  before relying on them for production-critical services.

## License

Apache-2.0 — see [LICENSE](LICENSE).
