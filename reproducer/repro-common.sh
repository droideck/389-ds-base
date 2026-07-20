# Shared container-identity helpers, sourced by setup-389ds.sh,
# setup-openldap.sh, and run-benchmark.sh (each defines die() first).
#
# Container names are derived from this checkout's absolute path so that
# parallel worktrees/clones of the repo get disjoint containers, and an
# ownership label lets every script refuse to touch a container that belongs
# to a different checkout. Override the derived names with REPRO_389DS_NAME /
# REPRO_OPENLDAP_NAME when intentionally sharing or A/B-ing containers.

REPRO_SRC_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPRO_SRC_HASH="$(printf '%s' "$REPRO_SRC_ROOT" | shasum | cut -c1-8)"
REPRO_LABEL_KEY="org.389ds.repro.source"

NAME_389DS="${REPRO_389DS_NAME:-repro-389ds-$REPRO_SRC_HASH}"
NAME_OPENLDAP="${REPRO_OPENLDAP_NAME:-repro-openldap-$REPRO_SRC_HASH}"

# refuse_foreign <container>: no-op if the container does not exist; die if it
# exists without our ownership label (not created by this harness) or with a
# label pointing at a different checkout. Callers may rm -f only after this.
refuse_foreign() {
    local owner
    owner=$(docker inspect -f "{{index .Config.Labels \"$REPRO_LABEL_KEY\"}}" "$1" 2>/dev/null) \
        || return 0
    if [ -z "$owner" ]; then
        die "container $1 exists but was not created by this harness (no $REPRO_LABEL_KEY label) - remove it manually or set REPRO_*_NAME"
    fi
    if [ "$owner" != "$REPRO_SRC_ROOT" ]; then
        die "container $1 belongs to checkout $owner (this checkout: $REPRO_SRC_ROOT) - refusing to touch it"
    fi
}
