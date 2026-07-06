"""Checks phase: pure judgement over facts (P0 catalog).

Checks consume facts from the bus and produce Findings. They never touch
the system directly (leapp Checks discipline), which keeps them unit-
testable with synthetic facts.

Knowledge data (extras topic mapping, removed packages, runtime minimums)
lives in data/*.json; loaded via ctx["data"].
"""
import re

from .engine import registry, Finding

IMDS_RE = re.compile(r"(169\.254\.169\.254|http://instance-data)")
IMDS_TOKEN_RE = re.compile(r"X-aws-ec2-metadata-token", re.I)
CGROUP_V1_RE = re.compile(r"/sys/fs/cgroup/(memory|cpu|cpuacct|blkio)/")
EXTRAS_CMD_RE = re.compile(r"amazon-linux-extras\s+(install|enable)\s+(\S+)")
YUM_TOOL_RE = re.compile(r"\b(yum-config-manager|yum-cron|yum-plugin-\S+)\b")


def _parse_java(version):
    """Return (major, update) e.g. '1.8.0_252' -> (8, 252), '11.0.14' -> (11, 14)."""
    if not version:
        return None
    m = re.match(r"1\.(\d+)\.0_(\d+)", version)
    if m:
        return int(m.group(1)), int(m.group(2))
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
    if m:
        return int(m.group(1)), int(m.group(3))
    m = re.match(r"(\d+)", version)
    return (int(m.group(1)), 0) if m else None


@registry.check("epel-packages-in-use")
def check_epel(bus, ctx):
    """EPEL-origin packages, triaged against AL2023 core and SPAL.

    SPAL (Supplementary Packages for Amazon Linux, since AL2023.9 2025-11)
    rebuilds thousands of EPEL9 packages for AL2023, so many EPEL7 packages
    now have a drop-in path. Caveats: SPAL is 'as-is' from upstream EPEL9,
    NOT covered by AWS Support Plans, and gets no AWS CVE tracking.
    """
    repos = bus.consume_one("Repositories", {}).get("repos", [])
    rpms = bus.consume_one("InstalledRPMs", {}).get("packages", [])
    epel_enabled = any("epel" in r["repoid"].lower() and r["enabled"] for r in repos)
    fedora_pkgs = sorted(set(
        p["name"] for p in rpms if "fedora" in p["vendor"].lower()))
    if not epel_enabled and not fedora_pkgs:
        return []
    core = ctx["data"].get("al2023_core_packages", set())
    spal = ctx["data"].get("spal_packages", set())
    in_core = [p for p in fedora_pkgs if p in core]
    in_spal = [p for p in fedora_pkgs if p not in core and p in spal]
    uncovered = [p for p in fedora_pkgs if p not in core and p not in spal]

    findings = []
    if uncovered or (epel_enabled and not fedora_pkgs):
        summary = ("The epel repository is enabled. " if epel_enabled else "")
        if fedora_pkgs:
            summary += ("%d of %d EPEL-origin packages have no AL2023 core or "
                        "SPAL equivalent: %s"
                        % (len(uncovered), len(fedora_pkgs), ", ".join(uncovered[:15])))
        else:
            summary += "No EPEL-origin packages detected despite enabled repo."
        findings.append(Finding(
            key="epel-packages-in-use",
            title="%d EPEL-origin packages with no AL2023/SPAL path" % len(uncovered)
                  if uncovered else "EPEL repository enabled — no EPEL for AL2023",
            summary=summary,
            severity="high", effort="large", blocker=bool(uncovered),
            groups=["repository", "packages"],
            remediation="Re-source each package: build from source, use a "
                        "vendor repo, or containerize.",
            links=["https://docs.aws.amazon.com/linux/al2023/ug/epel.html"],
            related_resources=[("package", p) for p in uncovered[:20]],
        ))
    if in_spal:
        findings.append(Finding(
            key="epel-packages-spal-covered",
            title="%d EPEL-origin packages available via SPAL — enable the "
                  "amazonlinux-spal repository" % len(in_spal),
            summary="Available from SPAL (EPEL9 rebuild): %s. CAUTION: SPAL "
                    "packages are provided as-is from upstream EPEL9, are NOT "
                    "covered by AWS Support Plans, and receive no AWS CVE "
                    "tracking — acceptable for tooling, review for "
                    "production-critical services." % ", ".join(in_spal[:15]),
            severity="medium", effort="small", blocker=False,
            groups=["repository", "packages"],
            remediation="Enable SPAL on the new AL2023 instance "
                        "(requires release 2023.9.20251117+), then dnf install. "
                        "WARNING: EPEL7 -> EPEL9 is a major version jump — "
                        "applications depending on these packages may not work "
                        "correctly; test them against the new versions before "
                        "cutover.",
            links=["https://docs.aws.amazon.com/linux/al2023/ug/spal.html"],
            related_resources=[("package", p) for p in in_spal[:20]],
        ))
    if in_core:
        findings.append(Finding(
            key="epel-packages-core-covered",
            title="%d EPEL-origin packages absorbed into AL2023 core" % len(in_core),
            summary="Installable directly with dnf on AL2023: %s. WARNING: "
                    "versions differ from EPEL7 — AL2023 core ships newer "
                    "releases, and applications depending on these packages "
                    "may not work correctly (changed config-file formats, "
                    "CLI flags, defaults, plugin/module APIs, or dropped "
                    "features)."
                    % ", ".join(in_core[:15]),
            severity="low", effort="small", blocker=False,
            groups=["repository", "packages"],
            remediation="dnf install on the new instance, then TEST the "
                        "dependent applications against the new versions "
                        "before cutover (compare 'rpm -q <pkg>' on both sides "
                        "and review upstream changelogs for major jumps).",
        ))
    return findings


@registry.check("extras-topics-in-use")
def check_extras(bus, ctx):
    repos = bus.consume_one("Repositories", {}).get("repos", [])
    topics = [r["repoid"].replace("amzn2extra-", "")
              for r in repos if r["repoid"].startswith("amzn2extra-") and r["enabled"]]
    if not topics:
        return []
    mapping = ctx["data"].get("extras_topics", {})
    core = ctx["data"].get("al2023_core_packages", set())
    spal = ctx["data"].get("spal_packages", set())

    def disposition(topic):
        """Curated mapping first; else look the topic name up in the
        core/SPAL package DBs so newly-covered topics still get guidance."""
        target = mapping.get(topic, {}).get("al2023")
        if target:
            return target
        base = re.sub(r"[\d.]+$", "", topic)  # php8.0 -> php, redis6 -> redis
        for candidate in (topic, base):
            if candidate in core:
                return "%s (core repository)" % candidate
            if candidate in spal:
                return "%s (SPAL repository, as-is support)" % candidate
        return None

    resolved = {t: disposition(t) for t in topics}
    # 'epel' is scored by the dedicated package-level epel checks — mentioning
    # it here as a second blocker would double-count the same root cause
    unmapped = [t for t in topics if resolved[t] is None and t != "epel"]
    lines = []
    for t in topics:
        if t == "epel":
            lines.append("epel -> see the epel-packages-* findings "
                         "(scored there, not here)")
        else:
            lines.append("%s -> %s" % (t, resolved[t] or "NO AL2023 EQUIVALENT"))
    # all topics mapped -> mechanical provisioning rewrite, not a real risk
    return [Finding(
        key="extras-topics-in-use",
        title="%d amazon-linux-extras topics enabled — mechanism removed in AL2023"
              % len(topics),
        summary="Enabled topics and their AL2023 disposition: " + "; ".join(lines),
        severity="high" if unmapped else "medium",
        effort="medium" if unmapped else "small",
        blocker=bool(unmapped),
        groups=["repository", "packages"],
        remediation="Rewrite provisioning to dnf using the per-topic guidance "
                    "above. Topics marked '(SPAL repository)' need the "
                    "amazonlinux-spal repo enabled on the new instance "
                    "(release 2023.9.20251117+; as-is support, no AWS Support "
                    "Plan coverage). Topics with no equivalent need "
                    "re-sourcing or containerization.",
        links=["https://docs.aws.amazon.com/linux/al2023/ug/compare-with-al2.html",
               "https://docs.aws.amazon.com/linux/al2023/ug/spal.html"],
        related_resources=[("extras-topic", t) for t in topics],
    )]


@registry.check("packages-missing-in-al2023")
def check_missing_packages(bus, ctx):
    rpms = bus.consume_one("InstalledRPMs", {}).get("packages", [])
    removed = ctx["data"].get("removed_packages", {})
    hits = []
    for p in rpms:
        if p["name"] in removed:
            hits.append((p["name"], removed[p["name"]]))
    if not hits:
        return []
    lines = ["%s (%s)" % (name, info.get("replacement", "removed, no replacement"))
             for name, info in hits]
    no_replacement = any(not info.get("replacement") for _n, info in hits)
    return [Finding(
        key="packages-missing-in-al2023",
        title="%d installed packages are removed or replaced in AL2023" % len(hits),
        summary="Affected: " + "; ".join(lines),
        severity="high" if no_replacement else "medium",
        effort="medium" if no_replacement else "small",
        blocker=no_replacement,
        groups=["packages"],
        remediation="Adopt the listed replacements; packages without a "
                    "replacement need an alternative or removal.",
        links=["https://docs.aws.amazon.com/linux/al2023/ug/deprecated-al2.html"],
        related_resources=[("package", n) for n, _i in hits],
    )]


_OS_VENDORS = ("amazon linux", "amazon.com")


@registry.check("python2-dependents")
def check_python2(bus, ctx):
    """Python 2 consumers, split into what matters and what doesn't.

    python 2.7 and the OS-bundled packages that depend on it (yum stack,
    cloud-init deps, ...) ship on EVERY stock AL2 and simply disappear with
    the redeployment — they carry no migration cost and must not affect the
    score. Only user-side consumers count: py2-shebang scripts and
    third-party (non-Amazon-vendor) packages chained to python 2.7.
    """
    rt = bus.consume_one("Runtimes", {})
    scripts = bus.consume_one("ScriptSources", {}).get("sources", {})
    shebang_hits = [path for path, text in scripts.items()
                    if re.match(r"#!.*\bpython2?\s*$", text.split("\n", 1)[0])]
    dependents = rt.get("python2_dependents", [])
    os_deps = [n for n, v in dependents if v.lower().startswith(_OS_VENDORS)]
    # EPEL-origin py2 dependents are already scored by epel-packages-in-use;
    # cross-reference them here instead of double-counting
    epel_deps = [n for n, v in dependents if "fedora" in v.lower()]
    user_deps = [n for n, v in dependents
                 if not v.lower().startswith(_OS_VENDORS)
                 and "fedora" not in v.lower()]
    processes = rt.get("python2_processes", [])

    findings = []
    if shebang_hits or user_deps or processes:
        parts = []
        if shebang_hits:
            parts.append("%d scripts use a python/python2 shebang: %s"
                         % (len(shebang_hits), ", ".join(shebang_hits[:8])))
        if processes:
            parts.append("%d python2 processes are RUNNING right now: %s"
                         % (len(processes),
                            "; ".join("pid %s (%s)" % (p["pid"], p["cmdline"][:80])
                                      for p in processes[:5])))
        if user_deps:
            parts.append("%d third-party packages depend on python 2.7: %s"
                         % (len(user_deps), ", ".join(sorted(user_deps)[:10])))
        if epel_deps:
            parts.append("(%d EPEL-origin py2 packages — %s — are scored "
                         "under the epel-packages-* findings)"
                         % (len(epel_deps), ", ".join(sorted(epel_deps)[:6])))
        findings.append(Finding(
            key="python2-dependents",
            title="Python 2 dependencies found — Python 2 is removed in AL2023",
            summary="; ".join(parts) + ".",
            severity="high", effort="medium", blocker=True,
            groups=["runtime"],
            remediation="Port scripts to python3 (AL2023 system python is 3.9). "
                        "If the scripts use the AWS SDK, boto2 code must move "
                        "to boto3. Replace third-party py2 packages with their "
                        "python3 builds.",
            links=["https://docs.aws.amazon.com/linux/al2023/ug/python.html"],
            related_resources=[("file", p) for p in shebang_hits[:15]] +
                              [("package", n) for n in sorted(user_deps)[:15]] +
                              [("process", "pid %s" % p["pid"]) for p in processes[:10]],
        ))
    elif rt.get("python2_installed"):
        # informational only: stock python2 stack, zero score impact
        findings.append(Finding(
            key="python2-os-stack-only",
            title="Python 2.7 present but only the AL2 OS stack depends on it "
                  "— no migration cost",
            summary="python 2.7 RPM is installed and %d OS-bundled packages "
                    "depend on it (%s...). These are part of the stock AL2 "
                    "image and simply do not exist on AL2023; no action needed. "
                    "No user scripts or third-party packages depend on python 2."
                    % (len(os_deps), ", ".join(sorted(os_deps)[:6])),
            severity="info", effort="trivial", blocker=False,
            groups=["runtime"],
            remediation="None — the python2 stack disappears with redeployment.",
        ))
    return findings


@registry.check("imdsv1-callers")
def check_imdsv1(bus, ctx):
    scripts = bus.consume_one("ScriptSources", {}).get("sources", {})
    rpms = bus.consume_one("InstalledRPMs", {}).get("packages", [])
    hits = []
    for path, text in scripts.items():
        if IMDS_RE.search(text) and not IMDS_TOKEN_RE.search(text):
            hits.append(path)
    boto2 = any(p["name"] in ("python-boto", "python2-boto") for p in rpms)
    if not hits and not boto2:
        return []
    summary = ""
    if hits:
        summary += ("%d scripts call the instance metadata service without an "
                    "IMDSv2 token header: %s. " % (len(hits), ", ".join(hits[:8])))
    if boto2:
        summary += "Legacy boto2 package installed (no IMDSv2 support)."
    return [Finding(
        key="imdsv1-callers",
        title="IMDSv1-style metadata access — will get 401 on AL2023 (IMDSv2 required)",
        summary=summary,
        severity="high", effort="small", blocker=True,
        groups=["metadata", "security"],
        remediation="Switch to the IMDSv2 token flow (PUT token, then GET with "
                    "X-aws-ec2-metadata-token). Note: AL2023 AMI default hop "
                    "limit is 2, so containers are not affected by default.",
        links=["https://docs.aws.amazon.com/linux/al2023/ug/imdsv2.html"],
        related_resources=[("file", p) for p in hits[:20]],
    )]


@registry.check("libssl10-linked-binaries")
def check_libssl10(bus, ctx):
    bins = bus.consume_one("ForeignBinaries", {}).get("binaries", [])
    hits = [b["path"] for b in bins
            if any(n.startswith(("libssl.so.10", "libcrypto.so.10",
                                 "libssl.so.1.0", "libcrypto.so.1.0"))
                   for n in b["needed"])]
    if not hits:
        return []
    return [Finding(
        key="libssl10-linked-binaries",
        title="%d binaries linked against OpenSSL 1.0.x — absent in AL2023" % len(hits),
        summary="These binaries require libssl.so.10/libcrypto.so.10, which "
                "AL2023 (OpenSSL 3.x only) does not ship: " + ", ".join(hits[:10]),
        severity="high", effort="large", blocker=True,
        groups=["runtime", "security"],
        remediation="Obtain an el9/AL2023 build from the vendor or rebuild "
                    "against OpenSSL 3.x.",
        links=["https://docs.aws.amazon.com/linux/al2023/ug/openssl.html"],
        related_resources=[("file", p) for p in hits[:20]],
    )]


@registry.check("cgroupv2-unsafe-runtimes")
def check_cgroupv2(bus, ctx):
    rt = bus.consume_one("Runtimes", {})
    scripts = bus.consume_one("ScriptSources", {}).get("sources", {})
    findings = []
    parsed = _parse_java(rt.get("java_version"))
    minimums = ctx["data"].get("java_cgroupv2_minimums", {"8": 372, "11": 16, "15": 0})
    if parsed:
        major, update = parsed
        needed = minimums.get(str(major))
        if needed is not None and update < needed:
            findings.append(Finding(
                key="cgroupv2-unsafe-runtimes",
                title="JDK %s cannot read cgroup v2 memory limits (needs %du%d+)"
                      % (rt["java_version"], major, needed),
                summary="On AL2023 (cgroup v2 only) this JVM sizes its heap from "
                        "host memory instead of the container/service limit, "
                        "risking OOM kills.",
                severity="high", effort="small", blocker=False,
                groups=["runtime", "cgroup"],
                remediation="Upgrade to Corretto 8u372+/11.0.16+/17+.",
                links=["https://docs.aws.amazon.com/AmazonECS/latest/developerguide/al2-to-al2023-ami-transition.html"],
            ))
    v1_hits = [p for p, text in scripts.items() if CGROUP_V1_RE.search(text)]
    if v1_hits:
        findings.append(Finding(
            key="cgroupv1-hardcoded-paths",
            title="%d scripts hardcode cgroup v1 paths — invalid on AL2023" % len(v1_hits),
            summary="cgroup v1 controller paths (/sys/fs/cgroup/memory, ...) do "
                    "not exist under cgroup v2: " + ", ".join(v1_hits[:8]),
            severity="medium", effort="small", blocker=False,
            groups=["cgroup"],
            remediation="Port to the cgroup v2 unified hierarchy interfaces.",
            related_resources=[("file", p) for p in v1_hits[:20]],
        ))
    return findings


@registry.check("userdata-bootstrap-breakage")
def check_userdata(bus, ctx):
    scripts = bus.consume_one("ScriptSources", {}).get("sources", {})
    hits = []
    for path, text in scripts.items():
        reasons = []
        for m in EXTRAS_CMD_RE.finditer(text):
            reasons.append("amazon-linux-extras %s %s" % (m.group(1), m.group(2)))
        for m in YUM_TOOL_RE.finditer(text):
            reasons.append(m.group(1))
        if "awslogs" in text:
            reasons.append("awslogs reference")
        if "/etc/eks/bootstrap.sh" in text:
            reasons.append("EKS bootstrap.sh (replaced by nodeadm)")
        if reasons:
            hits.append((path, sorted(set(reasons))))
    if not hits:
        return []
    lines = ["%s: %s" % (p, ", ".join(r)) for p, r in hits[:8]]
    return [Finding(
        key="userdata-bootstrap-breakage",
        title="Provisioning scripts use AL2-only mechanisms — will fail silently on AL2023",
        summary="Affected files: " + "; ".join(lines),
        severity="high", effort="medium", blocker=True,
        groups=["bootstrap"],
        remediation="Rewrite with dnf and AL2023 package names; replace awslogs "
                    "with the unified CloudWatch agent; use nodeadm for EKS nodes.",
        links=["https://docs.aws.amazon.com/linux/al2023/ug/compare-with-al2.html"],
        related_resources=[("file", p) for p, _r in hits[:20]],
    )]


@registry.check("i686-binaries")
def check_32bit(bus, ctx):
    rpms = bus.consume_one("InstalledRPMs", {}).get("packages", [])
    bins = bus.consume_one("ForeignBinaries", {}).get("binaries", [])
    i686_rpms = [p["name"] for p in rpms if p["arch"] in ("i686", "i386")]
    elf32 = [b["path"] for b in bins if b["is_32bit"]]
    if not i686_rpms and not elf32:
        return []
    summary = ""
    if i686_rpms:
        summary += "%d i686 RPMs installed: %s. " % (len(i686_rpms), ", ".join(i686_rpms[:10]))
    if elf32:
        summary += "%d 32-bit ELF binaries found: %s." % (len(elf32), ", ".join(elf32[:8]))
    return [Finding(
        key="i686-binaries",
        title="32-bit userspace in use — AL2023 ships no i686 packages",
        summary=summary,
        severity="high", effort="rebuild", blocker=True,
        groups=["packages", "runtime"],
        remediation="Obtain 64-bit builds, or run the 32-bit workload inside an "
                    "AL2 container on AL2023 (AWS-documented workaround).",
        links=["https://docs.aws.amazon.com/linux/al2023/ug/compare-with-al2.html"],
        related_resources=[("package", n) for n in i686_rpms[:10]] +
                          [("file", p) for p in elf32[:10]],
    )]


@registry.check("third-party-kernel-modules")
def check_kernel_modules(bus, ctx):
    km = bus.consume_one("KernelModules", {})
    oot = km.get("out_of_tree", [])
    dkms = km.get("dkms_status", "")
    kmods = km.get("kmod_pkgs", [])
    if not oot and not dkms and not kmods:
        return []
    parts = []
    if oot:
        parts.append("out-of-tree modules loaded: %s"
                     % ", ".join(m["module"] for m in oot[:8]))
    if dkms:
        parts.append("dkms-managed modules present")
    if kmods:
        parts.append("kmod packages installed: %s" % ", ".join(kmods[:5]))
    return [Finding(
        key="third-party-kernel-modules",
        title="Third-party kernel modules — must be rebuilt for the AL2023 6.x kernel",
        summary="; ".join(parts) + ". AL2 modules (kernel 4.14/5.10) will not "
                "load on the AL2023 6.1+ kernel.",
        severity="high", effort="large", blocker=False,
        groups=["kernel", "drivers"],
        remediation="Check vendor support for kernel 6.1+; rebuild DKMS modules "
                    "on an AL2023 test instance before cutover.",
        related_resources=[("kernel-module", m["module"]) for m in oot[:10]],
    )]


@registry.check("removed-daemons")
def check_removed_daemons(bus, ctx):
    cfg = bus.consume_one("SystemConfigs", {})
    findings = []
    if cfg.get("ntp_pkg") or cfg.get("ntp_conf"):
        findings.append(Finding(
            key="ntp-to-chrony",
            title="ntpd in use — AL2023 is chrony-only",
            summary="ntp package/config detected. Custom peers or ntpq-based "
                    "monitoring must be ported to chrony.",
            severity="medium", effort="small", groups=["services", "time"],
            remediation="Translate /etc/ntp.conf to /etc/chrony.conf; replace "
                        "ntpq checks with chronyc.",
            related_resources=[("file", "/etc/ntp.conf")],
        ))
    if cfg.get("rsyslog_remote"):
        findings.append(Finding(
            key="rsyslog-remote-forwarding",
            title="rsyslog remote forwarding configured — rsyslog not installed by default on AL2023",
            summary="Remote log forwarding rules found in rsyslog config. A "
                    "fresh AL2023 instance logs to journald only.",
            severity="medium", effort="small", groups=["services", "logging"],
            remediation="Install rsyslog via dnf on the new instance and carry "
                        "the forwarding rules, or move to the CloudWatch agent.",
            related_resources=[("file", "/etc/rsyslog.conf")],
        ))
    if cfg.get("awslogs_conf"):
        findings.append(Finding(
            key="awslogs-agent-removed",
            title="Legacy awslogs agent configured — removed in AL2023",
            summary="/etc/awslogs exists. The old CloudWatch Logs agent does "
                    "not exist on AL2023; log shipping would silently stop.",
            severity="medium", effort="small", blocker=True, groups=["logging"],
            remediation="Migrate the log group mappings to the unified "
                        "CloudWatch agent configuration.",
            related_resources=[("file", "/etc/awslogs")],
        ))
    if cfg.get("sendmail_conf"):
        findings.append(Finding(
            key="sendmail-removed",
            title="sendmail configuration present — sendmail removed in AL2023",
            summary="/etc/mail exists; AL2023 recommends postfix.",
            severity="medium", effort="small", groups=["services", "mail"],
            remediation="Port mail relay settings to postfix.",
        ))
    backends = cfg.get("authconfig_enabled_backends", [])
    if backends or cfg.get("nsswitch_nis"):
        findings.append(Finding(
            key="auth-chain-changes",
            title="authconfig/NIS-era auth chain detected — authselect on AL2023, NIS removed",
            summary=("authconfig enables non-local backends: %s. " % ", ".join(backends)
                     if backends else "") +
                    ("nsswitch.conf references nis. " if cfg.get("nsswitch_nis") else ""),
            severity="high", effort="large", groups=["security", "authentication"],
            remediation="Rebuild the auth stack with authselect/SSSD; NIS "
                        "environments need a redesign (e.g. LDAP/IAM).",
        ))
    return findings


@registry.check("network-scripts-customization")
def check_network(bus, ctx):
    cfg = bus.consume_one("SystemConfigs", {})
    custom = cfg.get("network_scripts_custom", [])
    hooks = cfg.get("dhclient_hooks", [])
    ipt = cfg.get("iptables_services")
    if not custom and not hooks and not ipt:
        return []
    parts = []
    if custom:
        parts.append("custom ifcfg/route files: %s" % ", ".join(custom[:6]))
    if hooks:
        parts.append("dhclient hooks/config present")
    if ipt:
        parts.append("iptables-services installed")
    return [Finding(
        key="network-scripts-customization",
        title="Legacy network-scripts customization — AL2023 uses systemd-networkd",
        summary="; ".join(parts) + ". ifcfg files and dhclient hooks are not "
                "read by the AL2023 network stack.",
        severity="medium", effort="medium", groups=["network"],
        remediation="Recreate static routes/secondary IPs as systemd-networkd "
                    "or EC2-level (ENI) configuration; port firewall rules to nftables.",
        links=["https://docs.aws.amazon.com/linux/al2023/ug/networking-service.html"],
        related_resources=[("file", p) for p in custom[:10]],
    )]


@registry.check("cron-jobs-present")
def check_cron(bus, ctx):
    scripts = bus.consume_one("ScriptSources", {}).get("sources", {})
    cron_files = [p for p in scripts
                  if "/cron" in p or p == "/etc/crontab" or p.startswith("/var/spool/cron")]
    cron_files = [p for p in cron_files
                  if scripts[p].strip() and not all(
                      l.strip().startswith("#") or not l.strip()
                      for l in scripts[p].splitlines())]
    if not cron_files:
        return []
    return [Finding(
        key="cron-jobs-present",
        title="%d active cron sources — cronie is not installed by default on AL2023"
              % len(cron_files),
        summary="Cron entries found in: " + ", ".join(cron_files[:10]) +
                ". On a fresh AL2023 instance these jobs will not run until "
                "cronie is installed.",
        severity="low", effort="trivial", groups=["services"],
        remediation="Install cronie in the new image (dnf install cronie) or "
                    "convert jobs to systemd timers.",
        related_resources=[("file", p) for p in cron_files[:10]],
    )]


@registry.check("tls-legacy-config")
def check_tls_legacy(bus, ctx):
    cfg = bus.consume_one("SystemConfigs", {})
    tls_hits = cfg.get("tls_legacy", [])
    weak_certs = cfg.get("weak_certs", [])
    findings = []
    if tls_hits:
        findings.append(Finding(
            key="tls-legacy-config",
            title="%d config lines pin TLS 1.0/1.1 — refused by the AL2023 "
                  "default crypto-policy" % len(tls_hits),
            summary="AL2023 sets MinProtocol=TLSv1.2 system-wide. These "
                    "directives will either fail or be silently overridden: " +
                    "; ".join("%s: '%s'" % (h["file"], h["line"])
                              for h in tls_hits[:6]),
            severity="medium", effort="small", blocker=False,
            groups=["security", "network"],
            remediation="Move clients/peers to TLS 1.2+. If a legacy peer is "
                        "unavoidable, a relaxed crypto-policy can be set on "
                        "AL2023 — but treat that as temporary debt.",
            links=["https://docs.aws.amazon.com/linux/al2023/ug/openssl.html"],
            related_resources=[("file", h["file"]) for h in tls_hits[:10]],
        ))
    if weak_certs:
        findings.append(Finding(
            key="weak-signature-certs",
            title="%d local certificates use MD5/SHA1 signatures — rejected "
                  "on AL2023" % len(weak_certs),
            summary="The AL2023 default crypto-policy rejects SHA1/MD5-signed "
                    "certificates in TLS: " +
                    "; ".join("%s (%s)" % (c["file"], c["sig_alg"])
                              for c in weak_certs[:6]),
            severity="medium", effort="small", blocker=False,
            groups=["security"],
            remediation="Re-issue the certificates with SHA-256 or newer "
                        "before cutover.",
            related_resources=[("file", c["file"]) for c in weak_certs[:10]],
        ))
    return findings


@registry.check("awscli-v1-scripts")
def check_awscli_v1(bus, ctx):
    rt = bus.consume_one("Runtimes", {})
    scripts = bus.consume_one("ScriptSources", {}).get("sources", {})
    if rt.get("aws_cli_major") != 1:
        return []
    callers = [p for p, text in scripts.items()
               if re.search(r"(^|[;&|`$(\s])aws\s+\w", text, re.M)]
    if not callers:
        return []
    return [Finding(
        key="awscli-v1-scripts",
        title="AWS CLI v1 installed and used by %d scripts — AL2023 ships "
              "CLI v2" % len(callers),
        summary="CLI v2 changes output defaults (pager, JSON formatting, "
                "base64 handling, S3 output) that can break scripted parsing. "
                "Callers: " + ", ".join(callers[:8]),
        severity="medium", effort="small", blocker=False,
        groups=["tooling"],
        remediation="Test each script against CLI v2; set cli_pager= and "
                    "explicit --output json where parsing depends on v1 "
                    "behavior.",
        links=["https://docs.aws.amazon.com/cli/latest/userguide/cliv2-migration-changes.html"],
        related_resources=[("file", p) for p in callers[:10]],
    )]


# directives dropped or non-functional under systemd 252 (AL2023) vs 219 (AL2)
_SYSTEMD_DEPRECATED_RE = re.compile(
    r"^\s*(MemoryLimit|CPUShares|StartLimitInterval(?=\s*=)|BlockIOWeight"
    r"|BlockIOReadBandwidth|BlockIOWriteBandwidth|CPUAccounting\s*=\s*false"
    r"|PermissionsStartOnly)\b", re.M)

_SYSTEMD_REPLACEMENTS = {
    "MemoryLimit": "MemoryMax (cgroup v2)",
    "CPUShares": "CPUWeight (cgroup v2)",
    "BlockIOWeight": "IOWeight (cgroup v2)",
    "BlockIOReadBandwidth": "IOReadBandwidthMax",
    "BlockIOWriteBandwidth": "IOWriteBandwidthMax",
    "StartLimitInterval": "StartLimitIntervalSec ([Unit] section)",
    "PermissionsStartOnly": "ExecStart=+... prefix",
}


@registry.check("systemd-deprecated-directives")
def check_systemd_deprecated(bus, ctx):
    scripts = bus.consume_one("ScriptSources", {}).get("sources", {})
    hits = {}
    for path, text in scripts.items():
        if not path.endswith(".service"):
            continue
        found = sorted(set(m.group(1).split()[0].rstrip("=")
                           for m in _SYSTEMD_DEPRECATED_RE.finditer(text)))
        if found:
            hits[path] = found
    if not hits:
        return []
    lines = ["%s: %s" % (p, ", ".join(
        "%s -> %s" % (d, _SYSTEMD_REPLACEMENTS.get(d, "see systemd 252 docs"))
        for d in ds)) for p, ds in sorted(hits.items())]
    return [Finding(
        key="systemd-deprecated-directives",
        title="%d custom units use directives deprecated by systemd 252 "
              "(AL2 ships 219)" % len(hits),
        summary="Old cgroup-v1 era directives are ignored or renamed on "
                "AL2023: " + "; ".join(lines[:6]),
        severity="low", effort="small", blocker=False,
        groups=["services"],
        remediation="Update each unit to the cgroup-v2 equivalents shown "
                    "above and re-test resource limits on AL2023.",
        related_resources=[("file", p) for p in sorted(hits)[:10]],
    )]


@registry.check("third-party-agents")
def check_vendors(bus, ctx):
    rpms = bus.consume_one("InstalledRPMs", {}).get("packages", [])
    third = sorted(set(
        p["name"] for p in rpms
        if p["vendor"] not in ("Amazon Linux", "Amazon.com", "(none)")
        and "fedora" not in p["vendor"].lower()))
    if not third:
        return []
    return [Finding(
        key="third-party-agents",
        title="%d third-party vendor packages installed — verify AL2023 support" % len(third),
        summary="Non-Amazon vendor packages: " + ", ".join(third[:20]) +
                ". Each vendor's AL2023 (el9-era) support matrix and minimum "
                "agent version must be confirmed.",
        severity="info", effort="small", groups=["packages", "vendors"],
        remediation="Check each vendor's documentation for AL2023 builds and "
                    "repository URLs (el7 repo paths will not work).",
        related_resources=[("package", n) for n in third[:20]],
    )]
