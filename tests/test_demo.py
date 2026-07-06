"""Demo/regression test: feed synthetic facts for a legacy AL2 host through
the checks and render the report — verifies the engine end-to-end without
needing a real AL2 instance (checks run against synthetic facts, no system access needed).

Run: python3 tests/test_demo.py
"""
import datetime
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from al2023_preflight.engine import Bus, registry, run_assessment  # noqa: E402
from al2023_preflight import checks  # noqa: F401,E402 (register checks)
from al2023_preflight.report import build_json, render_txt, render_summary_box  # noqa: E402


def synthetic_legacy_host(bus):
    """A worst-ish case AL2 pet server: EPEL, extras, py2, IMDSv1, 32bit..."""
    bus.produce("InstalledRPMs", {"packages": [
        {"name": "fail2ban", "version": "0.11", "arch": "noarch", "vendor": "Fedora Project"},
        {"name": "syslog-ng", "version": "3.5", "arch": "x86_64", "vendor": "Fedora Project"},
        {"name": "htop", "version": "2.2", "arch": "x86_64", "vendor": "Fedora Project"},
        {"name": "python2-simplejson", "version": "3.10", "arch": "x86_64", "vendor": "Fedora Project"},
        {"name": "ntp", "version": "4.2", "arch": "x86_64", "vendor": "Amazon Linux"},
        {"name": "awslogs", "version": "1.1", "arch": "noarch", "vendor": "Amazon Linux"},
        {"name": "python", "version": "2.7.18", "arch": "x86_64", "vendor": "Amazon Linux"},
        {"name": "libstdc++", "version": "4.8", "arch": "i686", "vendor": "Amazon Linux"},
        {"name": "datadog-agent", "version": "7.38", "arch": "x86_64", "vendor": "Datadog"},
        {"name": "splunkforwarder", "version": "8.2", "arch": "x86_64", "vendor": "Splunk Inc"},
        {"name": "yum-cron", "version": "3.4", "arch": "noarch", "vendor": "Amazon Linux"},
    ]})
    bus.produce("Repositories", {"repos": [
        {"repoid": "amzn2-core", "file": "/etc/yum.repos.d/amzn2-core.repo", "enabled": True},
        {"repoid": "epel", "file": "/etc/yum.repos.d/epel.repo", "enabled": True},
        {"repoid": "amzn2extra-docker", "file": "/etc/yum.repos.d/amzn2extra-docker.repo", "enabled": True},
        {"repoid": "amzn2extra-epel", "file": "/etc/yum.repos.d/amzn2extra-epel.repo", "enabled": True},
        {"repoid": "amzn2extra-nginx1", "file": "/etc/yum.repos.d/amzn2extra-nginx1.repo", "enabled": True},
    ]})
    bus.produce("ForeignBinaries", {"binaries": [
        {"path": "/opt/vendor-agent/bin/agentd", "is_32bit": False,
         "needed": ["libssl.so.10", "libcrypto.so.10", "libc.so.6"]},
        {"path": "/opt/legacy-tool/bin/report32", "is_32bit": True,
         "needed": ["libc.so.6"]},
    ]})
    bus.produce("ScriptSources", {"sources": {
        "/var/lib/cloud/instance/user-data.txt":
            "#!/bin/bash\namazon-linux-extras install nginx1 -y\n"
            "yum-config-manager --enable epel\nyum install -y awslogs\n",
        "/usr/local/bin/push-metrics.sh":
            "#!/bin/bash\nID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)\n",
        "/etc/cron.d/backup":
            "0 2 * * * root /usr/local/bin/backup.sh "
            "$(curl http://instance-data/latest/meta-data/local-ipv4)\n",
        "/usr/local/bin/legacy-report.py":
            "#!/usr/bin/python\nimport boto\n",
        "/usr/local/bin/mem-watch.sh":
            "#!/bin/bash\ncat /sys/fs/cgroup/memory/docker/memory.limit_in_bytes\n",
        "/etc/systemd/system/myapp.service":
            "[Service]\nExecStart=/opt/myapp/run\nMemoryLimit=2G\n"
            "CPUShares=512\n",
        "/usr/local/bin/deploy-info.sh":
            "#!/bin/bash\naws ec2 describe-instances --query ...\n",
    }})
    bus.produce("SystemConfigs", {
        "ntp_conf": True, "ntp_pkg": True,
        "rsyslog_remote": True, "sendmail_conf": False,
        "awslogs_conf": True, "authconfig_enabled_backends": ["LDAP"],
        "nsswitch_nis": False,
        "network_scripts_custom": ["/etc/sysconfig/network-scripts/route-eth0"],
        "dhclient_hooks": [], "iptables_services": False, "eks_bootstrap": False,
        "tls_legacy": [{"file": "/etc/httpd/conf.d/ssl.conf",
                        "line": "SSLProtocol all -SSLv3 TLSv1 TLSv1.1"}],
        "weak_certs": [{"file": "/etc/pki/tls/certs/legacy.crt",
                        "sig_alg": "sha1WithRSAEncryption"}],
    })
    bus.produce("KernelModules", {
        "loaded": ["xt_conntrack", "vendor_secmod"],
        "out_of_tree": [{"module": "vendor_secmod",
                         "path": "/lib/modules/4.14.355/extra/vendor_secmod.ko"}],
        "dkms_status": "", "kmod_pkgs": [],
    })
    bus.produce("Runtimes", {
        "java_version": "1.8.0_252", "python2_installed": True,
        "python2_dependents": [
            ("pygpgme", "Amazon Linux"),          # OS stack -> ignored
            ("yum-metadata-parser", "Amazon Linux"),
            ("python2-custom-lib", "ACME Corp"),  # third-party -> flagged
        ],
        "python2_processes": [
            {"pid": "8714", "cmdline": "/usr/bin/python2 /opt/myapp/daemon.py"}],
        "usr_bin_python": "/usr/bin/python2.7",
        "docker_version": "Docker version 20.10.25, build b82b9f3",
        "aws_cli_major": 1,
    })


def main():
    from al2023_preflight.cli import load_data
    data = load_data()
    ctx = {"data": data}

    # run checks directly against a synthetic bus (bypass real scanners)
    bus = Bus()
    synthetic_legacy_host(bus)
    findings = []
    failed = []
    for name, fn in registry.checks:
        try:
            findings.extend(fn(bus, ctx) or [])
        except Exception as e:
            failed.append((name, repr(e)))

    assert not failed, "checks crashed: %s" % failed

    from al2023_preflight.engine import compute_grade, SEVERITY_ORDER
    findings.sort(key=lambda f: (not f.blocker, SEVERITY_ORDER[f.severity], -f.score))
    grade, score, effort = compute_grade(findings)

    meta = {"version": "0.1.0-demo", "data_version": data["data_version"],
            "hostname": "web-legacy-01", "instance_id": "i-0abc1234def567890",
            "scanned_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}
    doc = build_json(meta, findings, grade, score, effort)

    # --- assertions on expected P0 detections ---
    keys = {f.key for f in findings}
    expected = {
        "epel-packages-in-use", "extras-topics-in-use",
        "packages-missing-in-al2023", "python2-dependents", "imdsv1-callers",
        "libssl10-linked-binaries", "cgroupv2-unsafe-runtimes",
        "cgroupv1-hardcoded-paths", "userdata-bootstrap-breakage",
        "i686-binaries", "third-party-kernel-modules", "ntp-to-chrony",
        "rsyslog-remote-forwarding", "awslogs-agent-removed",
        "auth-chain-changes", "network-scripts-customization",
        "cron-jobs-present", "third-party-agents",
        "tls-legacy-config", "weak-signature-certs", "awscli-v1-scripts",
        "systemd-deprecated-directives",
    }
    missing = expected - keys
    assert not missing, "expected findings not raised: %s" % missing
    assert doc["counts"]["blocker"] >= 5, "expected >=5 blockers, got %s" % doc["counts"]
    assert grade in ("D", "E"), "legacy host should grade D/E, got %s" % grade

    print(render_txt(doc))
    print(render_summary_box(doc))
    print("\nTEST PASSED: %d findings, %d blockers, grade %s (score %d, effort %s)"
          % (len(findings), doc["counts"]["blocker"], grade, score, effort))


if __name__ == "__main__":
    main()
