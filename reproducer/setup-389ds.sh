#!/usr/bin/env bash
# Stand up the repro-389ds container: privileged systemd container from the
# 389-ds CI image with the locally built RPMs installed, then create an
# instance, add the reproducer schema + indexes, and import data.ldif.
#
# Container startup mirrors ~/bin/389ds-container `shell` mode (which itself
# mirrors .github/workflows/pytest.yml), minus the pytest bits. The container
# is left RUNNING for later interactive investigation.
#
# Prereqs: ./data.ldif + schema/99reproducer.ldif exist (run generate-data.py
# first) and ../dist/rpms/ holds current 389-ds-base RPMs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# Overridable so a container can be built from another checkout's RPMs
# (e.g. a baseline build in a sibling clone) while using this harness.
RPMS_DIR="${REPRO_RPMS_DIR:-$REPO_ROOT/dist/rpms}"

IMAGE="${DS_CONTAINER_IMAGE:-quay.io/389ds/ci-images:test}"
PLATFORM="linux/amd64"

# Exported into every in-container step below.
INSTANCE="repro"
SUFFIX="dc=example,dc=com"
ROOT_DN="cn=Directory Manager"
PASSWORD="${REPRO_DM_PASSWORD:-Reproducer123}"

die() { echo "error: $*" >&2; exit 1; }

# shellcheck source=repro-common.sh
source "$SCRIPT_DIR/repro-common.sh"
NAME="$NAME_389DS"

case "$PASSWORD" in
    *%*|*[[:space:]]*|*'"'*|*"'"*)
        # '%' breaks dscreate's INF parser (configparser interpolation);
        # whitespace/quotes break the generated config lines.
        die "REPRO_DM_PASSWORD must not contain %, whitespace, or quotes" ;;
esac

in_container() {  # run stdin as a bash script inside the container
    docker exec -i \
        -e INSTANCE="$INSTANCE" -e SUFFIX="$SUFFIX" \
        -e ROOT_DN="$ROOT_DN" -e PASSWORD="$PASSWORD" \
        "$NAME" bash -s
}

[[ -f "$SCRIPT_DIR/data.ldif" ]] || die "data.ldif missing - run generate-data.py first"
[[ -f "$SCRIPT_DIR/schema/99reproducer.ldif" ]] || die "schema/99reproducer.ldif missing"
compgen -G "$RPMS_DIR/*.rpm" >/dev/null || die "no RPMs in $RPMS_DIR"
docker info >/dev/null 2>&1 || die "docker daemon not reachable"

echo ">> starting container $NAME ($IMAGE, $PLATFORM)"
refuse_foreign "$NAME"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --platform="$PLATFORM" \
    --name "$NAME" \
    --label "$REPRO_LABEL_KEY=$REPRO_SRC_ROOT" \
    -h repro389.example.com \
    --ulimit core=-1 \
    --cap-add=SYS_PTRACE \
    --privileged \
    --shm-size=4gb \
    -v "$SCRIPT_DIR:/repro" \
    -v "$RPMS_DIR:/rpms:ro" \
    "$IMAGE" >/dev/null

echo ">> waiting for systemd..."
tries=0
until docker exec "$NAME" sh -c \
        'systemctl is-system-running 2>/dev/null | grep -qE "^(running|degraded)$"'; do
    tries=$((tries + 1))
    (( tries > 120 )) && die "systemd in $NAME did not become ready in 120s"
    sleep 1
done

echo ">> installing RPMs..."
in_container <<'EOS'
set -euo pipefail
mkdir -p /etc/sysconfig
printf "%s\n" "HARDLINK=no" > /etc/sysconfig/kernel
rpms=$(find /rpms -maxdepth 1 -type f -name "*.rpm" \
    ! -name "*-debuginfo-*.rpm" \
    ! -name "*-debugsource-*.rpm" \
    ! -name "*-devel-*.rpm" | sort)
[ -n "$rpms" ] || { echo "no non-debug RPMs found in /rpms" >&2; exit 1; }
dnf install -y -q $rpms openldap-clients
# dbus may fail to start under emulation; not required for slapd.
systemctl start dbus.service 2>&1 || echo "(dbus.service did not start - tolerated)"
# Rosetta/emulation: same MemoryDenyWriteExecute drop-in the CI wrapper uses.
mkdir -p /etc/systemd/system/dirsrv@.service.d
printf "%s\n" "[Service]" "MemoryDenyWriteExecute=no" \
    > /etc/systemd/system/dirsrv@.service.d/rosetta-mdwe.conf
systemctl daemon-reload
EOS

echo ">> creating instance $INSTANCE..."
in_container <<'EOS'
set -euo pipefail
cat > /tmp/repro.inf <<EOF
[general]
config_version = 2
full_machine_name = repro389.example.com
start = True

[slapd]
instance_name = $INSTANCE
root_dn = $ROOT_DN
root_password = $PASSWORD
port = 389
secure_port = 636
self_sign_cert = False

[backend-userroot]
suffix = $SUFFIX
create_suffix_entry = True
EOF
dscreate from-file /tmp/repro.inf
EOS

echo ">> installing reproducer schema + restarting..."
in_container <<'EOS'
set -euo pipefail
cp /repro/schema/99reproducer.ldif "/etc/dirsrv/slapd-$INSTANCE/schema/"
chmod 644 "/etc/dirsrv/slapd-$INSTANCE/schema/99reproducer.ldif"
dsctl "$INSTANCE" restart
EOS

echo ">> configuring: access log unbuffered, indexes..."
in_container <<'EOS'
set -euo pipefail
dsc() { dsconf -D "$ROOT_DN" -w "$PASSWORD" ldap://localhost:389 "$@"; }

# Flush access log per line so per-run etime is visible immediately, and
# disable time-based rotation: run-benchmark.sh windows the log by line
# offset and refuses to record if rotation shifts the window mid-benchmark.
dsc config replace nsslapd-accesslog-logbuffering=off
dsc config replace nsslapd-accesslog-logrotationtime=-1

dsc backend index add --attr reproTitle    --index-type eq --index-type sub --index-type pres userRoot
dsc backend index add --attr reproDept     --index-type eq --index-type sub --index-type pres userRoot
dsc backend index add --attr reproTag      --index-type eq userRoot
dsc backend index add --attr reproRegion   --index-type eq userRoot
dsc backend index add --attr reproMailAlt  --index-type eq userRoot
dsc backend index add --attr reproHostname --index-type eq userRoot
dsc backend index add --attr reproManager  --index-type eq userRoot
dsc backend index add --attr reproScore    --index-type eq --matching-rule integerOrderingMatch userRoot
dsc backend index add --attr reproLevel    --index-type eq --matching-rule integerOrderingMatch userRoot
# reproFlag and reproNote stay deliberately UNINDEXED.

# cn/uid/objectClass ship as default indexes; assert the assumptions the
# README documents (cn eq,sub,pres; uid eq; objectClass eq).
names=$(dsc backend index list --just-names userRoot)
for a in cn uid objectclass; do
    echo "$names" | grep -qix "$a" || { echo "default index missing: $a" >&2; exit 1; }
done
dsc backend index get --attr cn userRoot | grep -qiE '^nsindextype: *pres' \
    || dsc backend index set --attr cn --add-type pres userRoot
EOS

echo ">> importing data.ldif (online import), then full reindex..."
in_container <<'EOS'
set -euo pipefail
dsc() { dsconf -D "$ROOT_DN" -w "$PASSWORD" ldap://localhost:389 "$@"; }
mkdir -p "/var/lib/dirsrv/slapd-$INSTANCE/ldif"
cp /repro/data.ldif "/var/lib/dirsrv/slapd-$INSTANCE/ldif/data.ldif"
chown dirsrv:dirsrv "/var/lib/dirsrv/slapd-$INSTANCE/ldif/data.ldif"
dsc backend import userRoot "/var/lib/dirsrv/slapd-$INSTANCE/ldif/data.ldif"
dsc backend index reindex --wait userRoot
EOS

echo ">> verifying (bound as $ROOT_DN)..."
in_container <<'EOS'
set -euo pipefail
search() { ldapsearch -x -H ldap://localhost:389 -D "$ROOT_DN" -w "$PASSWORD" "$@"; }

search -b "$SUFFIX" -s sub '(uid=user0000000)' 1.1 \
    | grep -q '^dn: uid=user0000000' \
    || { echo "verification search failed" >&2; exit 1; }

# Import warnings (skipped entries) exit 0 in dsconf, so assert the exact
# entry count against data.ldif rather than trusting the import task.
expected=$(grep -c '^dn: uid=' /repro/data.ldif || true)
[ "${expected:-0}" -gt 0 ] || { echo "no user entries in /repro/data.ldif?" >&2; exit 1; }
actual=$(search -b "ou=people,$SUFFIX" -s base numSubordinates \
    | awk 'tolower($1)=="numsubordinates:" {print $2}')
[ "$actual" = "$expected" ] \
    || { echo "entry count mismatch: numSubordinates=$actual expected=$expected (import skipped entries?)" >&2; exit 1; }

# Functional index spot-checks with data-derived expected counts: a silently
# failed reindex returns wrong candidate sets, not errors, so compare counts.
for probe in "reproTag=taggolden000" "reproScore=500" "reproScore=501"; do
    attr=${probe%%=*}; val=${probe#*=}
    exp=$(grep -c "^${attr}: ${val}\$" /repro/data.ldif || true)
    [ "${exp:-0}" -gt 0 ] || { echo "probe value $probe not in data.ldif?" >&2; exit 1; }
    got=$(search -b "$SUFFIX" -s sub "($probe)" 1.1 | grep -c '^dn:' || true)
    [ "$got" = "$exp" ] \
        || { echo "index spot-check ($probe): got $got expected $exp" >&2; exit 1; }
done

# Substring preflight: the benchmark's costly components are substring
# assertions, so a missing/broken cn sub index changes what is being
# MEASURED, not just correctness. Check the index type in config AND a
# functional substring count against the data.
dsc() { dsconf -D "$ROOT_DN" -w "$PASSWORD" ldap://localhost:389 "$@"; }
dsc backend index get --attr cn userRoot | grep -qiE '^nsindextype: *sub' \
    || { echo "cn index has no sub type" >&2; exit 1; }
fat_exp=$(grep -c "^cn: .*Megaword\$" /repro/data.ldif || true)
[ "${fat_exp:-0}" -gt 0 ] || { echo "no Megaword cn values in data.ldif - regenerate data" >&2; exit 1; }
got=$(search -b "$SUFFIX" -s sub "(cn=*megaword*)" 1.1 | grep -c '^dn:' || true)
[ "$got" = "$fat_exp" ] \
    || { echo "substring spot-check (cn=*megaword*): got $got expected $fat_exp" >&2; exit 1; }
echo "verified: $expected entries, index + substring spot-checks passed"
EOS

mkdir -p "$SCRIPT_DIR/results"
docker exec "$NAME" rpm -q 389-ds-base > "$SCRIPT_DIR/results/389ds-version.txt"
echo ">> done. container $NAME is running; version: $(cat "$SCRIPT_DIR/results/389ds-version.txt")"
echo ">> re-enter with: docker exec -it $NAME bash"
