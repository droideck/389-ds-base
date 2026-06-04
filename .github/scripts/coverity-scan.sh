#!/bin/bash

set -euo pipefail

COVERITY_PROJECT="${COVERITY_PROJECT:-389ds/389-ds-base}"
COVERITY_BUILD_LANGUAGE="${COVERITY_BUILD_LANGUAGE:-cxx}"
COVERITY_BUILD_PLATFORM="${COVERITY_BUILD_PLATFORM:-linux64}"
COVERITY_BASE_URL="https://scan.coverity.com"

github_escape() {
    local value="$1"

    value="${value//'%'/'%25'}"
    value="${value//$'\r'/'%0D'}"
    value="${value//$'\n'/'%0A'}"
    printf '%s' "${value}"
}

github_error() {
    local title="$1"
    local message="$2"

    printf '::error title=%s::%s\n' "$(github_escape "${title}")" "$(github_escape "${message}")"
}

fail() {
    local title="$1"
    local message="$2"

    github_error "${title}" "${message}"
    exit 1
}

project_url() {
    local encoded="${COVERITY_PROJECT}"

    encoded="${encoded//%/%25}"
    encoded="${encoded// /%20}"
    encoded="${encoded//\//%2F}"
    printf '%s' "${encoded}"
}

download_url() {
    printf '%s/download/%s/%s' "${COVERITY_BASE_URL}" "${COVERITY_BUILD_LANGUAGE}" "${COVERITY_BUILD_PLATFORM}"
}

upload_url() {
    printf '%s/builds?project=%s' "${COVERITY_BASE_URL}" "$(project_url)"
}

require_env() {
    local name="$1"
    local message="$2"

    if [ -z "${!name:-}" ]; then
        fail "Missing ${name}" "${message}"
    fi
}

content_type_from_headers() {
    local headers="$1"

    awk '
        {
            raw = $0
            line = tolower(raw)
            if (line ~ /^content-type:/) {
                sub(/\r$/, "", raw)
                sub(/^[^:]*:[[:space:]]*/, "", raw)
                value = raw
            }
        }
        END { print value }
    ' "${headers}"
}

file_size() {
    wc -c < "$1" | tr -d '[:space:]'
}

response_kind() {
    local body="$1"

    if [ ! -s "${body}" ]; then
        printf 'empty'
    elif grep -qiE '<[[:space:]]*(html|head|body)|<!doctype' "${body}"; then
        printf 'HTML'
    elif LC_ALL=C grep -q '[^[:print:][:space:]]' "${body}"; then
        printf 'binary'
    else
        printf 'text'
    fi
}

redact_known_secrets() {
    local value="$1"

    if [ -n "${COVERITY_SCAN_TOKEN:-}" ]; then
        value="${value//${COVERITY_SCAN_TOKEN}/[redacted-token]}"
    fi

    if [ -n "${COVERITY_SCAN_EMAIL:-}" ]; then
        value="${value//${COVERITY_SCAN_EMAIL}/[redacted-email]}"
    fi

    printf '%s' "${value}"
}

sanitize_text() {
    local value="$1"

    value="$(redact_known_secrets "${value}")"
    printf '%s' "${value}" |
        LC_ALL=C tr '\r\n\t' '   ' |
        LC_ALL=C tr -c '[:print:]' '?' |
        sed -e 's/[[:space:]][[:space:]]*/ /g' -e 's/^ //' -e 's/ $//'
}

response_preview() {
    local body="$1"
    local value

    value="$(LC_ALL=C head -c 240 "${body}" | LC_ALL=C tr '\000' '?')"
    sanitize_text "${value}"
}

stderr_preview() {
    local stderr_file="$1"
    local value

    value="$(LC_ALL=C head -c 240 "${stderr_file}" | LC_ALL=C tr '\000' '?')"
    sanitize_text "${value}"
}

curl_capture() {
    local title="$1"
    local body="$2"
    local headers="$3"
    local stderr_file="$4"
    local http_code
    local curl_status

    shift 4

    set +e
    http_code="$(curl \
        --silent \
        --show-error \
        --location \
        --output "${body}" \
        --dump-header "${headers}" \
        --write-out "%{http_code}" \
        "$@" \
        2>"${stderr_file}")"
    curl_status=$?
    set -e

    if [ "${curl_status}" -ne 0 ]; then
        local stderr_text

        stderr_text="$(stderr_preview "${stderr_file}")"
        fail "${title} failed" "curl exited with status ${curl_status} before a valid HTTP response. ${stderr_text:+curl stderr: ${stderr_text}. }Check Coverity service status and network access."
    fi

    printf '%s' "${http_code}"
}

fail_response() {
    local title="$1"
    local expected="$2"
    local http_code="$3"
    local body="$4"
    local headers="$5"
    local content_type
    local size
    local kind
    local preview

    content_type="$(content_type_from_headers "${headers}")"
    size="$(file_size "${body}")"
    kind="$(response_kind "${body}")"
    preview="$(response_preview "${body}")"

    fail "${title}" "Expected ${expected} for ${COVERITY_PROJECT}; got HTTP ${http_code}, content-type '${content_type:-unknown}', ${size} bytes, response kind '${kind}'. ${preview:+Response preview: ${preview}. }Check Coverity service status, COVERITY_SCAN_TOKEN, and project access."
}

with_temp_response() {
    local body
    local headers
    local stderr_file

    body="${1:-}"
    if [ -z "${body}" ]; then
        body="$(mktemp)"
        RESPONSE_BODY_TEMP="${body}"
    else
        RESPONSE_BODY_TEMP=
    fi

    headers="$(mktemp)"
    stderr_file="$(mktemp)"

    RESPONSE_BODY="${body}"
    RESPONSE_HEADERS="${headers}"
    RESPONSE_STDERR="${stderr_file}"
}

cleanup_temp_response() {
    rm -f "${RESPONSE_BODY_TEMP:-}" "${RESPONSE_HEADERS:-}" "${RESPONSE_STDERR:-}"
}

validate_env() {
    local missing=0

    if [ -z "${COVERITY_SCAN_EMAIL:-}" ]; then
        github_error "Missing Coverity email" "Set the COVERITY_SCAN_EMAIL repository secret."
        missing=1
    fi

    if [ -z "${COVERITY_SCAN_TOKEN:-}" ]; then
        github_error "Missing Coverity token" "Set the COVERITY_SCAN_TOKEN repository secret."
        missing=1
    fi

    exit "${missing}"
}

lookup_hash() {
    local http_code
    local hash

    require_env COVERITY_SCAN_TOKEN "Set the COVERITY_SCAN_TOKEN repository secret."
    require_env GITHUB_OUTPUT "GITHUB_OUTPUT is required for the Coverity hash output."

    with_temp_response
    trap cleanup_temp_response EXIT

    http_code="$(curl_capture \
        "Coverity checksum lookup" \
        "${RESPONSE_BODY}" \
        "${RESPONSE_HEADERS}" \
        "${RESPONSE_STDERR}" \
        --data "token=${COVERITY_SCAN_TOKEN}&project=$(project_url)&md5=1" \
        "$(download_url)")"

    hash="$(tr -d '\r\n' < "${RESPONSE_BODY}")"

    if [ "${http_code}" != "200" ] || ! printf '%s' "${hash}" | grep -Eq '^[0-9a-fA-F]{32}$'; then
        fail_response "Coverity checksum lookup failed" "HTTP 200 with a 32-character md5 checksum" "${http_code}" "${RESPONSE_BODY}" "${RESPONSE_HEADERS}"
    fi

    printf 'hash=%s\n' "${hash}" >> "${GITHUB_OUTPUT}"
}

install_tool() {
    local http_code

    require_env COVERITY_SCAN_TOKEN "Set the COVERITY_SCAN_TOKEN repository secret."

    rm -f cov-analysis.tar.gz

    with_temp_response cov-analysis.tar.gz
    trap cleanup_temp_response EXIT

    http_code="$(curl_capture \
        "Coverity build tool download" \
        "${RESPONSE_BODY}" \
        "${RESPONSE_HEADERS}" \
        "${RESPONSE_STDERR}" \
        --data "token=${COVERITY_SCAN_TOKEN}&project=$(project_url)" \
        "$(download_url)")"

    if [ "${http_code}" != "200" ]; then
        fail_response "Coverity build tool download failed" "HTTP 200 with a gzip archive" "${http_code}" "${RESPONSE_BODY}" "${RESPONSE_HEADERS}"
    fi

    if ! gzip -t cov-analysis.tar.gz; then
        fail_response "Coverity build tool archive invalid" "a valid gzip archive" "${http_code}" "${RESPONSE_BODY}" "${RESPONSE_HEADERS}"
    fi

    mkdir -p cov-analysis
    tar -xzf cov-analysis.tar.gz --strip 1 -C cov-analysis
}

verify_tool() {
    if [ ! -x cov-analysis/bin/cov-build ]; then
        fail "Coverity build tool unavailable" "Expected executable cov-analysis/bin/cov-build after cache restore or install."
    fi
}

build() {
    verify_tool
    export PATH="${PWD}/cov-analysis/bin:${PATH}"
    cov-build --dir cov-int make
}

archive() {
    tar -czvf cov-int.tgz cov-int
}

submit() {
    local http_code
    local version
    local description
    local preview

    require_env COVERITY_SCAN_EMAIL "Set the COVERITY_SCAN_EMAIL repository secret."
    require_env COVERITY_SCAN_TOKEN "Set the COVERITY_SCAN_TOKEN repository secret."

    if [ ! -f cov-int.tgz ]; then
        fail "Coverity archive missing" "Expected cov-int.tgz before submitting results."
    fi

    version="${COVERITY_VERSION:-${GITHUB_SHA:-unknown}}"
    description="${COVERITY_DESCRIPTION:-coverity-scan-action ${GITHUB_REPOSITORY:-${COVERITY_PROJECT}} / ${GITHUB_REF:-unknown}}"

    with_temp_response
    trap cleanup_temp_response EXIT

    http_code="$(curl_capture \
        "Coverity result submission" \
        "${RESPONSE_BODY}" \
        "${RESPONSE_HEADERS}" \
        "${RESPONSE_STDERR}" \
        --form token="${COVERITY_SCAN_TOKEN}" \
        --form email="${COVERITY_SCAN_EMAIL}" \
        --form file=@cov-int.tgz \
        --form version="${version}" \
        --form description="${description}" \
        "$(upload_url)")"

    case "${http_code}" in
        2*)
            preview="$(response_preview "${RESPONSE_BODY}")"
            if [ -n "${preview}" ]; then
                printf '%s\n' "${preview}"
            fi
            ;;
        *)
            fail_response "Coverity result submission failed" "a 2xx response" "${http_code}" "${RESPONSE_BODY}" "${RESPONSE_HEADERS}"
            ;;
    esac
}

usage() {
    cat <<EOF
Usage: $0 <command>

Commands:
  validate-env
  lookup-hash
  install-tool
  verify-tool
  build
  archive
  submit
EOF
}

case "${1:-}" in
    validate-env)
        validate_env
        ;;
    lookup-hash)
        lookup_hash
        ;;
    install-tool)
        install_tool
        ;;
    verify-tool)
        verify_tool
        ;;
    build)
        build
        ;;
    archive)
        archive
        ;;
    submit)
        submit
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        usage
        exit 2
        ;;
esac
