#!/usr/bin/env bash
# Stand up the repro-openldap container: Fedora base image (same distro
# family as the 389-ds CI image), OpenLDAP with a plain slapd file config
# (mdb backend), reproducer schema, mirrored indexes, bulk load via
# slapadd -q, then slapd running with stats logging to /var/log/slapd-repro.log.
# The container is left RUNNING for later interactive investigation.
#
# Prereqs: ./data.ldif + schema/reproducer.schema exist (run generate-data.py
# first).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IMAGE="${OPENLDAP_CONTAINER_IMAGE:-fedora:42}"
PLATFORM="linux/amd64"

SUFFIX="dc=example,dc=com"
ROOT_DN="cn=Manager,dc=example,dc=com"
PASSWORD="${REPRO_DM_PASSWORD:-Reproducer123}"

die() { echo "error: $*" >&2; exit 1; }

# shellcheck source=repro-common.sh
source "$SCRIPT_DIR/repro-common.sh"
NAME="$NAME_OPENLDAP"

case "$PASSWORD" in
    *%*|*[[:space:]]*|*'"'*|*"'"*)
        # same charset rule as setup-389ds.sh (one env var drives both);
        # whitespace/quotes would break the generated slapd.conf rootpw line.
        die "REPRO_DM_PASSWORD must not contain %, whitespace, or quotes" ;;
esac

in_container() {
    docker exec -i \
        -e SUFFIX="$SUFFIX" -e ROOT_DN="$ROOT_DN" -e PASSWORD="$PASSWORD" \
        "$NAME" bash -s
}

[[ -f "$SCRIPT_DIR/data.ldif" ]] || die "data.ldif missing - run generate-data.py first"
[[ -f "$SCRIPT_DIR/schema/reproducer.schema" ]] || die "schema/reproducer.schema missing"
docker info >/dev/null 2>&1 || die "docker daemon not reachable"

echo ">> starting container $NAME ($IMAGE, $PLATFORM)"
refuse_foreign "$NAME"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --platform="$PLATFORM" \
    --name "$NAME" \
    --label "$REPRO_LABEL_KEY=$REPRO_SRC_ROOT" \
    -h reproldap.example.com \
    -v "$SCRIPT_DIR:/repro" \
    "$IMAGE" sleep infinity >/dev/null

echo ">> installing openldap-servers + openldap-clients..."
in_container <<'EOS'
set -euo pipefail
dnf install -y -q openldap-servers openldap-clients
for f in core cosine inetorgperson; do
    [ -f "/etc/openldap/schema/$f.schema" ] \
        || { echo "missing /etc/openldap/schema/$f.schema" >&2; exit 1; }
done
EOS

echo ">> writing slapd config (mdb, mirrored indexes, loglevel stats)..."
in_container <<'EOS'
set -euo pipefail
# Fedora builds the mdb backend as a module in some releases and statically
# in others; load it only if the module file exists.
MODLINES=""
if ls /usr/lib64/openldap/back_mdb* >/dev/null 2>&1; then
    MODLINES=$'modulepath /usr/lib64/openldap\nmoduleload back_mdb'
fi
cat > /etc/openldap/slapd-repro.conf <<EOF
include /etc/openldap/schema/core.schema
include /etc/openldap/schema/cosine.schema
include /etc/openldap/schema/inetorgperson.schema
include /repro/schema/reproducer.schema

pidfile  /run/slapd-repro.pid
argsfile /run/slapd-repro.args
loglevel stats
$MODLINES

database mdb
suffix   "$SUFFIX"
rootdn   "$ROOT_DN"
rootpw   $PASSWORD
directory /var/lib/ldap-repro
maxsize  4294967296

# Index parity with the 389-ds side (see README.md for the full table).
index objectClass  eq
index uid          eq
index cn           eq,sub,pres
index reproTitle   eq,sub,pres
index reproDept    eq,sub,pres
index reproTag     eq
index reproRegion  eq
index reproMailAlt eq
index reproHostname eq
index reproManager eq
index member       eq
index reproScore   eq
index reproLevel   eq
# reproFlag and reproNote stay deliberately UNINDEXED.
EOF
mkdir -p /var/lib/ldap-repro
EOS

echo ">> bulk-loading data.ldif with slapadd -q (this can take a while)..."
in_container <<'EOS'
set -euo pipefail
/usr/sbin/slapadd -q -f /etc/openldap/slapd-repro.conf -l /repro/data.ldif \
    > /var/log/slapadd.log 2>&1 \
    || { tail -20 /var/log/slapadd.log >&2; exit 1; }
tail -3 /var/log/slapadd.log || true
EOS

echo ">> starting slapd (stats debug output -> /var/log/slapd-repro.log)..."
# -d 256 = stats; keeps slapd in the foreground, so run it as a detached exec.
docker exec -d "$NAME" bash -c \
    '/usr/sbin/slapd -f /etc/openldap/slapd-repro.conf -h "ldap://0.0.0.0:389/" -d 256 >> /var/log/slapd-repro.log 2>&1'

echo ">> waiting for slapd to answer..."
tries=0
until docker exec "$NAME" ldapsearch -x -H ldap://localhost:389 -b '' -s base \
        namingContexts >/dev/null 2>&1; do
    tries=$((tries + 1))
    (( tries > 60 )) && { docker exec "$NAME" tail -30 /var/log/slapd-repro.log >&2 || true;
                          die "slapd did not become ready in 60s"; }
    sleep 1
done

echo ">> verifying (bound as $ROOT_DN)..."
in_container <<'EOS'
set -euo pipefail
search() { ldapsearch -x -H ldap://localhost:389 -D "$ROOT_DN" -w "$PASSWORD" "$@"; }

search -b "$SUFFIX" -s sub '(uid=user0000000)' 1.1 \
    | grep -q '^dn: uid=user0000000' \
    || { echo "verification search failed" >&2; exit 1; }

# Exact entry count vs data.ldif (rootdn is exempt from size limits, so a
# one-level search returns everything under ou=people).
expected=$(grep -c '^dn: uid=' /repro/data.ldif || true)
[ "${expected:-0}" -gt 0 ] || { echo "no user entries in /repro/data.ldif?" >&2; exit 1; }
actual=$(search -b "ou=people,$SUFFIX" -s one '(objectClass=*)' 1.1 | grep -c '^dn:' || true)
[ "$actual" = "$expected" ] \
    || { echo "entry count mismatch: got $actual expected $expected" >&2; exit 1; }

# Same functional index spot-checks as setup-389ds.sh.
for probe in "reproTag=taggolden000" "reproScore=500" "reproScore=501"; do
    attr=${probe%%=*}; val=${probe#*=}
    exp=$(grep -c "^${attr}: ${val}\$" /repro/data.ldif || true)
    [ "${exp:-0}" -gt 0 ] || { echo "probe value $probe not in data.ldif?" >&2; exit 1; }
    got=$(search -b "$SUFFIX" -s sub "($probe)" 1.1 | grep -c '^dn:' || true)
    [ "$got" = "$exp" ] \
        || { echo "index spot-check ($probe): got $got expected $exp" >&2; exit 1; }
done

# Same substring + index-type preflight as setup-389ds.sh.
grep -qE '^index +cn +.*sub' /etc/openldap/slapd-repro.conf \
    || { echo "cn index has no sub type in slapd-repro.conf" >&2; exit 1; }
fat_exp=$(grep -c "^cn: .*Megaword\$" /repro/data.ldif || true)
[ "${fat_exp:-0}" -gt 0 ] || { echo "no Megaword cn values in data.ldif - regenerate data" >&2; exit 1; }
got=$(search -b "$SUFFIX" -s sub "(cn=*megaword*)" 1.1 | grep -c '^dn:' || true)
[ "$got" = "$fat_exp" ] \
    || { echo "substring spot-check (cn=*megaword*): got $got expected $fat_exp" >&2; exit 1; }
echo "verified: $expected entries, index + substring spot-checks passed"
EOS

mkdir -p "$SCRIPT_DIR/results"
docker exec "$NAME" /usr/sbin/slapd -VV 2>&1 | head -3 > "$SCRIPT_DIR/results/openldap-version.txt" || true
echo ">> done. container $NAME is running; version: $(head -1 "$SCRIPT_DIR/results/openldap-version.txt")"
echo ">> re-enter with: docker exec -it $NAME bash"
