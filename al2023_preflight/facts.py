"""Facts phase: read-only scanners.

Each scanner only collects system state and produces fact messages on the
bus. No judgement here (leapp FactsCollection discipline: "no decision
should be done in this phase"). Every command is read-only.
"""
import glob
import os
import re
import subprocess

from .engine import registry


def _run(cmd, timeout=30):
    """Run a read-only command; returns stdout ('' on any failure)."""
    try:
        out = subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, timeout=timeout)
        return out.decode("utf-8", "replace")
    except Exception:
        return ""


def _read(path, limit=1024 * 1024):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read(limit)
    except Exception:
        return ""


@registry.scanner("rpm_scanner")
def scan_rpm(bus, ctx):
    out = _run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\t%{ARCH}\t%{VENDOR}\n"])
    pkgs = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 4:
            pkgs.append({"name": parts[0], "version": parts[1],
                         "arch": parts[2], "vendor": parts[3]})
    bus.produce("InstalledRPMs", {"packages": pkgs})
    vendors = set(p["vendor"] for p in pkgs
                  if p["vendor"] not in ("Amazon Linux", "Amazon.com", "(none)"))
    return "%d installed packages (%d third-party vendors)" % (len(pkgs), len(vendors))


@registry.scanner("repo_scanner")
def scan_repos(bus, ctx):
    repos = []
    for path in glob.glob("/etc/yum.repos.d/*.repo"):
        content = _read(path)
        for m in re.finditer(r"^\[([^\]]+)\]([^\[]*)", content, re.M):
            repoid, body = m.group(1), m.group(2)
            enabled = not re.search(r"^\s*enabled\s*=\s*0", body, re.M)
            repos.append({"repoid": repoid, "file": path, "enabled": enabled})
    extras = [r for r in repos if r["repoid"].startswith("amzn2extra-") and r["enabled"]]
    bus.produce("Repositories", {"repos": repos})
    n_enabled = sum(1 for r in repos if r["enabled"])
    epel = "epel found, " if any("epel" in r["repoid"] for r in repos if r["enabled"]) else ""
    return "%d enabled repositories (%s%d extras topics)" % (n_enabled, epel, len(extras))


@registry.scanner("binary_scanner")
def scan_binaries(bus, ctx):
    """Scan ELF binaries under /opt and /usr/local for linked libs and arch."""
    binaries = []
    roots = ctx.get("binary_roots", ["/opt", "/usr/local"])
    for root in roots:
        for dirpath, _dirs, files in os.walk(root):
            if len(binaries) >= 500:  # safety cap on huge trees
                break
            for fname in files:
                path = os.path.join(dirpath, fname)
                try:
                    with open(path, "rb") as f:
                        magic = f.read(5)
                except Exception:
                    continue
                if magic[:4] != b"\x7fELF":
                    continue
                is32 = len(magic) > 4 and magic[4] == 1
                needed = re.findall(r"NEEDED.*\[(.+?)\]", _run(["objdump", "-p", path]))
                if not needed:
                    needed = re.findall(r"^\s*(\S+\.so[.\d]*)\s+=>", _run(["ldd", path]), re.M)
                binaries.append({"path": path, "is_32bit": is32, "needed": needed})
    bus.produce("ForeignBinaries", {"binaries": binaries})
    return "%d ELF binaries scanned under %s" % (len(binaries), ", ".join(roots))


@registry.scanner("script_scanner")
def scan_scripts(bus, ctx):
    """Collect text of user-data, cron jobs, custom units, local scripts."""
    sources = {}
    userdata = "/var/lib/cloud/instance/user-data.txt"
    if os.path.exists(userdata):
        sources[userdata] = _read(userdata)
    cron_paths = (glob.glob("/etc/cron.d/*") + glob.glob("/etc/cron.daily/*") +
                  glob.glob("/etc/cron.hourly/*") + glob.glob("/var/spool/cron/*") +
                  ["/etc/crontab"])
    n_cron = 0
    for p in cron_paths:
        if os.path.isfile(p):
            sources[p] = _read(p)
            n_cron += 1
    unit_paths = glob.glob("/etc/systemd/system/*.service")
    for p in unit_paths:
        text = _read(p)
        sources[p] = text
        # follow ExecStart/ExecStartPre targets: the executable's shebang is
        # what matters, not just the unit file text
        for m in re.finditer(r"^Exec(?:Start|StartPre|StartPost)\s*=\s*"
                             r"[-@+!:]*(\S+)", text, re.M):
            target = m.group(1)
            if target.startswith("/") and target not in sources \
                    and os.path.isfile(target):
                head = _read(target, limit=64 * 1024)
                if head.startswith("#!"):
                    sources[target] = head
    for p in glob.glob("/usr/local/bin/*") + glob.glob("/usr/local/sbin/*"):
        if os.path.isfile(p):
            head = _read(p, limit=64 * 1024)
            if head.startswith("#!"):
                sources[p] = head
    bus.produce("ScriptSources", {"sources": sources})
    return "user-data, %d cron jobs, %d systemd units" % (n_cron, len(unit_paths))


# Files shipped by the AL2 base image / core packages — not user customization.
_AL2_DEFAULT_DHCLIENT = {
    "/etc/dhcp/dhclient.d/chrony.sh",            # chrony package
    "/etc/dhcp/dhclient.d/ec2dhcp.sh",           # ec2-net-utils package
    "/etc/dhcp/dhclient-enter-hooks.d/50_ec2_rewrite_primary_enter_hook.sh",
    "/etc/dhcp/dhclient-exit-hooks.d/azure-cloud.sh",   # cloud-init
    "/etc/dhcp/dhclient-exit-hooks.d/hook-dhclient",    # cloud-init
}
_AL2_DEFAULT_ROUTE_ETH0 = re.compile(
    r"^\s*169\.254\.169\.254\s+via\s+0\.0\.0\.0\s+dev\s+eth0\s*$")


def _custom_network_scripts():
    """ifcfg/route/rule files beyond the AL2 defaults.

    route-eth0 containing only the standard metadata-service static route
    (shipped on many stock AMIs) does not count as customization.
    """
    custom = []
    for p in glob.glob("/etc/sysconfig/network-scripts/*"):
        if not re.search(r"/(ifcfg-(?!eth0$|lo$)|route-|rule-)", p):
            continue
        if os.path.basename(p) == "route-eth0":
            lines = [l.strip() for l in _read(p).splitlines()
                     if l.strip() and not l.strip().startswith("#")]
            if all(_AL2_DEFAULT_ROUTE_ETH0.match(l) for l in lines):
                continue
        custom.append(p)
    return custom


def _custom_dhclient_hooks():
    """dhclient hook scripts that are not part of the stock AL2 image.

    dhclient.conf itself and package-shipped hooks are excluded; only
    admin-added hook scripts indicate a migration-relevant customization.
    """
    hooks = []
    for d in ("/etc/dhcp/dhclient.d", "/etc/dhcp/dhclient-enter-hooks.d",
              "/etc/dhcp/dhclient-exit-hooks.d"):
        for p in glob.glob(d + "/*"):
            if p not in _AL2_DEFAULT_DHCLIENT:
                hooks.append(p)
    return hooks


@registry.scanner("config_scanner")
def scan_configs(bus, ctx):
    facts = {
        "ntp_conf": os.path.exists("/etc/ntp.conf"),
        "ntp_pkg": bool(_run(["rpm", "-q", "ntp"]).startswith("ntp-")),
        "rsyslog_remote": bool(re.search(
            r"^\s*[^#]*(@@?[\w.-]+|target=)", _read("/etc/rsyslog.conf") +
            "".join(_read(p) for p in glob.glob("/etc/rsyslog.d/*.conf")), re.M)),
        "sendmail_conf": os.path.isdir("/etc/mail"),
        "awslogs_conf": os.path.isdir("/etc/awslogs"),
        # authconfig file exists by default on AL2 — only meaningful when a
        # non-local backend (LDAP/NIS/Kerberos/Winbind) is actually enabled
        "authconfig_enabled_backends": re.findall(
            r"^USE(LDAP|NIS|KERBEROS|WINBIND|SSSD)=yes",
            _read("/etc/sysconfig/authconfig"), re.M),
        # skip comment lines when looking for nis in nsswitch.conf
        "nsswitch_nis": bool(re.search(
            r"^\s*[^#\s]\S*:.*\bnis\b", _read("/etc/nsswitch.conf"), re.M)),
        "network_scripts_custom": _custom_network_scripts(),
        "dhclient_hooks": _custom_dhclient_hooks(),
        "iptables_services": bool(_run(["rpm", "-q", "iptables-services"]).startswith("iptables-services-")),
        "eks_bootstrap": os.path.exists("/etc/eks/bootstrap.sh"),
        "tls_legacy": _scan_tls_configs(),
        "weak_certs": _scan_weak_certs(),
    }
    bus.produce("SystemConfigs", facts)
    return "ntp/rsyslog/network-scripts/TLS configuration parsed"


_TLS_LEGACY_RE = re.compile(
    r"^\s*(SSLProtocol\b.*\bTLSv1(\.[01])?\b(?!\.[23])"   # httpd enabling v1/1.1
    r"|ssl_protocols\b[^;]*\bTLSv1(\.[01])?\b(?!\.[23])"  # nginx
    r"|ssl-min-ver\s+(SSLv3|TLSv1\.[01])"                  # haproxy
    r"|MinProtocol\s*=\s*(None|SSLv3|TLSv1(\.[01])?)$)",   # openssl.cnf
    re.M | re.I)


def _scan_tls_configs():
    """Web-server / proxy configs that pin TLS 1.0/1.1 — the AL2023 default
    crypto-policy refuses TLS < 1.2."""
    hits = []
    conf_globs = ["/etc/httpd/conf/*.conf", "/etc/httpd/conf.d/*.conf",
                  "/etc/nginx/nginx.conf", "/etc/nginx/conf.d/*.conf",
                  "/etc/nginx/sites-enabled/*", "/etc/haproxy/haproxy.cfg"]
    for pattern in conf_globs:
        for path in glob.glob(pattern):
            content = _read(path)
            for m in _TLS_LEGACY_RE.finditer(content):
                line = m.group(0).strip()
                # skip lines that merely disable old protocols (-TLSv1, !TLSv1)
                if re.search(r"[-!]\s*TLSv1", line):
                    continue
                hits.append({"file": path, "line": line[:120]})
    return hits


def _scan_weak_certs():
    """Local certificates signed with MD5/SHA1 — rejected by the AL2023
    default crypto-policy."""
    weak = []
    cert_paths = glob.glob("/etc/pki/tls/certs/*.crt") + \
        glob.glob("/etc/pki/tls/certs/*.pem") + \
        glob.glob("/etc/nginx/ssl/*") + glob.glob("/etc/httpd/ssl/*")
    for path in cert_paths[:100]:
        if os.path.islink(path) or not os.path.isfile(path):
            continue
        out = _run(["openssl", "x509", "-in", path, "-noout", "-text"])
        m = re.search(r"Signature Algorithm:\s*(\S+)", out)
        if m and re.search(r"(md5|sha1)", m.group(1), re.I):
            weak.append({"file": path, "sig_alg": m.group(1)})
    return weak


@registry.scanner("kernel_scanner")
def scan_kernel(bus, ctx):
    lsmod = _run(["lsmod"]).splitlines()[1:]
    modules = [l.split()[0] for l in lsmod if l.split()]
    out_of_tree = []
    for mod in modules:
        info = _run(["modinfo", "-F", "filename", mod]).strip()
        if info and ("/extra/" in info or "/updates/" in info or
                     not info.startswith("/lib/modules/")):
            out_of_tree.append({"module": mod, "path": info})
    dkms = _run(["dkms", "status"]).strip()
    bus.produce("KernelModules", {
        "loaded": modules, "out_of_tree": out_of_tree,
        "dkms_status": dkms,
        # kmod/kmod-libs are core packages, not third-party driver kmods
        "kmod_pkgs": [l for l in _run(["rpm", "-qa", "kmod-*"]).splitlines()
                      if l and not l.startswith(("kmod-libs-", "kmod-devel-"))],
    })
    return "%d loaded modules (%d out-of-tree)" % (len(modules), len(out_of_tree))


@registry.scanner("runtime_scanner")
def scan_runtimes(bus, ctx):
    java_raw = _run(["java", "-version"]) or _run(
        ["sh", "-c", "java -version 2>&1"])
    m = re.search(r'version "([^"]+)"', java_raw)
    java_version = m.group(1) if m else None
    python2 = bool(_run(["rpm", "-q", "python"]).startswith("python-2"))
    # packages that depend on python2 (ABI or shared lib) — lets the user see
    # exactly what is chained to python 2.7 before replatforming
    py2_dependents = set()
    for cap in ("python(abi) = 2.7", "libpython2.7.so.1.0()(64bit)"):
        out = _run(["rpm", "-q", "--whatrequires", cap,
                    "--qf", "%{NAME}\t%{VENDOR}\n"])
        for line in out.splitlines():
            if "\t" in line and "no package requires" not in line:
                name, vendor = line.split("\t", 1)
                py2_dependents.add((name, vendor))
    docker_raw = _run(["docker", "--version"])
    # live process list: catches py2 daemons whose script lives outside the
    # scanned paths (e.g. /opt/myapp) — read-only
    py2_processes = []
    # NOTE: "-eo pid=,args=" is a procps trap — everything after the first
    # '=' becomes the pid column header and args is never printed.
    # Separate -o flags give two headerless columns as intended.
    ps_out = _run(["ps", "-e", "-o", "pid=", "-o", "args="])
    for line in ps_out.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2:
            continue
        pid, cmdline = parts
        if re.search(r"(^|/)python2(\.\d+)?\b", cmdline.split()[0]) or \
                re.match(r"\S*/python\s", cmdline):
            py2_processes.append({"pid": pid, "cmdline": cmdline[:200]})

    aws_cli = _run(["aws", "--version"]) or _run(
        ["sh", "-c", "aws --version 2>&1"])
    m_cli = re.search(r"aws-cli/(\d+)\.", aws_cli)

    facts = {
        "java_version": java_version,
        "python2_installed": python2,
        "python2_dependents": sorted(py2_dependents),
        "python2_processes": py2_processes,
        "aws_cli_major": int(m_cli.group(1)) if m_cli else None,
        "usr_bin_python": os.path.realpath("/usr/bin/python")
        if os.path.exists("/usr/bin/python") else None,
        "docker_version": docker_raw.strip() or None,
    }
    bus.produce("Runtimes", facts)
    parts = []
    if java_version:
        parts.append("java %s" % java_version)
    if python2:
        parts.append("python 2.x present")
    if facts["docker_version"]:
        parts.append(facts["docker_version"].split(",")[0].lower())
    return ", ".join(parts) if parts else "no notable runtimes"
