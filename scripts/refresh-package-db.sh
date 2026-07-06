#!/usr/bin/env bash
# Regenerate the AL2023 package-existence DBs used by the epel/missing-package
# checks. Run on an up-to-date AL2023 host (release 2023.9.20251117+ so the
# amazonlinux-spal repo exists), then commit the refreshed files.
#
# Usage: ./scripts/refresh-package-db.sh [output-dir]
set -euo pipefail

OUTDIR="${1:-$(dirname "$0")/../al2023_preflight/data}"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RELEASE="$(cat /etc/system-release 2>/dev/null || echo unknown)"

if ! grep -q "Amazon Linux release 2023" /etc/system-release 2>/dev/null; then
    echo "ERROR: must run on an AL2023 host (found: ${RELEASE})" >&2
    exit 1
fi

gen() {
    local repo="$1" outfile="$2"
    echo "Querying ${repo}..."
    {
        echo "# repo: ${repo}"
        echo "# generated: ${STAMP} on ${RELEASE}"
        echo "# regenerate: scripts/refresh-package-db.sh (run on an up-to-date AL2023 host)"
        dnf repoquery --repo "${repo}" --qf '%{name}' 2>/dev/null | LC_ALL=C sort -u
    } > "${outfile}.tmp"
    # sanity: refuse to overwrite with a suspiciously small result
    local n
    n=$(grep -cv '^#' "${outfile}.tmp")
    if [ "${n}" -lt 1000 ]; then
        echo "ERROR: ${repo} returned only ${n} packages — repo disabled or query failed; keeping old file" >&2
        rm -f "${outfile}.tmp"
        return 1
    fi
    mv "${outfile}.tmp" "${outfile}"
    echo "  -> ${outfile} (${n} packages)"
}

gen amazonlinux      "${OUTDIR}/al2023-core-packages.txt"
gen amazonlinux-spal "${OUTDIR}/spal-packages.txt"
echo "Done. Review the diff and update data_version in knowledge.json if needed."
