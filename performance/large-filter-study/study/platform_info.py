"""Host, package, process, and artifact identity helpers for the study.

This module intentionally contains no package installation or build support.
The native runner treats an already installed server RPM as an immutable
precondition and records enough identity to audit that assertion later.
"""

from __future__ import annotations

import grp
import hashlib
import json
import os
import platform
import pwd
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


class StudyError(RuntimeError):
    """A user-facing validation or execution failure."""


DIRSRV_RUNTIME_LOCK_PATH = Path("/var/lock/dirsrv")
DIRSRV_RUNTIME_LOCK_VERIFY_FLAGS = ".....UG.."
RPM_VERIFY_LINE = re.compile(
    r"^(?P<flags>\S{9})\s+(?:(?P<file_type>[a-z])\s+)?(?P<path>/.*)$"
)


def command_path(name: str) -> str | None:
    found = shutil.which(name)
    return str(Path(found).resolve()) if found else None


def require_commands(names: Iterable[str]) -> dict[str, str]:
    found: dict[str, str] = {}
    missing: list[str] = []
    for name in names:
        path = command_path(name)
        if path:
            found[name] = path
        else:
            missing.append(name)
    if missing:
        raise StudyError("required executable(s) missing: " + ", ".join(missing))
    return found


def run_command(
    argv: Sequence[str | os.PathLike[str]],
    *,
    check: bool = True,
    timeout: float | None = None,
    env: Mapping[str, str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    args = [os.fspath(value) for value in argv]
    proc = subprocess.run(
        args,
        check=False,
        text=True,
        capture_output=True,
        timeout=timeout,
        env=dict(env) if env is not None else None,
        cwd=os.fspath(cwd) if cwd is not None else None,
        input=input_text,
    )
    if check and proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "no diagnostic output"
        raise StudyError(f"command failed ({proc.returncode}): {args[0]}: {detail}")
    return proc


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def capture_optional(argv: Sequence[str], *, timeout: float = 30.0) -> dict[str, Any]:
    try:
        proc = run_command(argv, check=False, timeout=timeout)
        return {
            "argv": list(argv),
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except (OSError, subprocess.TimeoutExpired) as error:
        return {
            "argv": list(argv),
            "returncode": None,
            "stdout": "",
            "stderr": str(error),
        }


def _container_kind() -> str | None:
    if Path("/.dockerenv").exists():
        return "docker-compatible"
    if Path("/run/.containerenv").exists():
        return "containerenv"
    detector = command_path("systemd-detect-virt")
    if detector:
        result = run_command([detector, "--container"], check=False, timeout=10)
        if result.returncode == 0 and result.stdout.strip() not in ("", "none"):
            return result.stdout.strip()
    return None


def _first_existing(paths: Iterable[Path]) -> str:
    for path in paths:
        text = read_text(path).strip()
        if text:
            return text
    return ""


def _cpu_governors() -> list[str]:
    values = {
        read_text(path).strip()
        for path in Path("/sys/devices/system/cpu").glob("cpu[0-9]*/cpufreq/scaling_governor")
        if read_text(path).strip()
    }
    return sorted(values)


def _lscpu_topology(captured: Mapping[str, Any] | None) -> dict[str, str]:
    if not isinstance(captured, Mapping) or captured.get("returncode") != 0:
        return {}
    try:
        payload = json.loads(str(captured.get("stdout", "")))
    except json.JSONDecodeError:
        return {}
    fields = payload.get("lscpu") if isinstance(payload, Mapping) else None
    if not isinstance(fields, list):
        return {}
    stable_prefixes = (
        "architecture", "cpu(s)", "on-line cpu(s) list", "vendor id",
        "model name", "thread(s) per core", "core(s) per socket",
        "socket(s)", "numa node(s)", "numa node", "virtualization",
    )
    result: dict[str, str] = {}
    for item in fields:
        if not isinstance(item, Mapping):
            continue
        field = str(item.get("field", "")).strip().rstrip(":").casefold()
        if field and any(
                field == prefix or field.startswith(prefix + " ")
                for prefix in stable_prefixes):
            result[field] = str(item.get("data", "")).strip()
    return result


def host_metadata(*, host_class: str, correctness_only: bool) -> dict[str, Any]:
    uname = platform.uname()
    lscpu = capture_optional(["lscpu", "--json"]) if command_path("lscpu") else None
    memory = capture_optional(["free", "-b"]) if command_path("free") else None
    storage = capture_optional([
        "lsblk", "-J", "-o",
        "NAME,TYPE,SIZE,MODEL,ROTA,TRAN,FSTYPE,FSVER,MOUNTPOINTS",
    ]) if command_path("lsblk") else None
    filesystems = capture_optional([
        "findmnt", "-J", "-T", "/", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS",
    ]) if command_path("findmnt") else None
    cpu_model = ""
    if Path("/proc/cpuinfo").exists():
        match = re.search(r"^(?:model name|Hardware)\s*:\s*(.+)$", read_text(Path("/proc/cpuinfo")), re.M)
        if match:
            cpu_model = match.group(1).strip()
    mem_total_kib = None
    mem_match = re.search(r"^MemTotal:\s+(\d+)\s+kB", read_text(Path("/proc/meminfo")), re.M)
    if mem_match:
        mem_total_kib = int(mem_match.group(1))
    fedora_release = read_text(Path("/etc/fedora-release")).strip()
    container = _container_kind()
    machine_id_sha256 = sha256_bytes(
        _first_existing([
            Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id"),
        ]).encode("utf-8")
    )
    cpu_governors = _cpu_governors()
    lscpu_topology = _lscpu_topology(lscpu)
    compatibility_material = {
        "host_class": host_class,
        "architecture": uname.machine,
        "fedora_release": fedora_release,
        "kernel_release": uname.release,
        "cpu_model": cpu_model,
        "memory_total_kib": mem_total_kib,
        "machine_id_sha256": machine_id_sha256,
        "cpu_governors": cpu_governors,
        "lscpu_topology": lscpu_topology,
        "storage": storage,
        "filesystems": filesystems,
    }
    compatibility_key = sha256_bytes(
        json.dumps(compatibility_material, sort_keys=True).encode("utf-8")
    )
    return {
        **compatibility_material,
        "compatibility_key": compatibility_key,
        "correctness_only": correctness_only,
        "release_timing_evidence": not correctness_only,
        "system": uname.system,
        "node": uname.node,
        "kernel_version": uname.version,
        "platform": platform.platform(),
        "container_kind": container,
        "virtualization": capture_optional(["systemd-detect-virt"]) if command_path("systemd-detect-virt") else None,
        "cpu_governors": cpu_governors,
        "lscpu_topology": lscpu_topology,
        "lscpu": lscpu,
        "memory": memory,
        "storage": storage,
        "filesystems": filesystems,
        "machine_id_sha256": machine_id_sha256,
    }


def native_fedora_rejection_reasons(
        *, system: str, machine: str, fedora_release: str,
        container_kind: str | None, apple_markers: Sequence[str],
        explicitly_emulated: bool) -> list[str]:
    """Evaluate the release boundary without rejecting ordinary Fedora VMs."""
    reasons: list[str] = []
    if system != "Linux":
        reasons.append(f"system is {system}, not Linux")
    if machine.casefold() not in {"x86_64", "amd64"}:
        reasons.append(f"architecture is {machine}, not x86_64/amd64")
    if not fedora_release.strip():
        reasons.append("/etc/fedora-release is absent")
    if container_kind:
        reasons.append(f"container detected ({container_kind})")
    if apple_markers:
        reasons.append(
            "Apple/Rosetta/OrbStack marker(s) detected: "
            + ", ".join(sorted(set(apple_markers)))
        )
    if explicitly_emulated:
        reasons.append("LFSTUDY_EMULATED marks this environment as emulated")
    return reasons


def _apple_emulation_markers() -> list[str]:
    markers: list[str] = []
    for path in (
            Path("/proc/sys/fs/binfmt_misc/rosetta"),
            Path("/run/host-services/rosetta"),
            Path("/mnt/mac")):
        if path.exists():
            markers.append(str(path))
    sources = {
        "uname-release": platform.release(),
        "uname-version": platform.version(),
        "platform": platform.platform(),
        "cpuinfo": read_text(Path("/proc/cpuinfo")),
        "dmi-sys-vendor": read_text(Path("/sys/class/dmi/id/sys_vendor")),
        "dmi-product-name": read_text(Path("/sys/class/dmi/id/product_name")),
        "dmi-board-vendor": read_text(Path("/sys/class/dmi/id/board_vendor")),
    }
    marker_pattern = re.compile(
        r"(?:orbstack|rosetta|apple\s+(?:inc\.?|silicon|virtualization))",
        re.I,
    )
    for label, value in sources.items():
        if marker_pattern.search(value):
            markers.append(label)
    for key, value in os.environ.items():
        if marker_pattern.search(key) or marker_pattern.search(value):
            markers.append(f"environment:{key}")
    return sorted(set(markers))


def enforce_native_fedora() -> None:
    reasons = native_fedora_rejection_reasons(
        system=platform.system(),
        machine=platform.machine(),
        fedora_release=read_text(Path("/etc/fedora-release")),
        container_kind=_container_kind(),
        apple_markers=_apple_emulation_markers(),
        explicitly_emulated=(
            os.environ.get("LFSTUDY_EMULATED", "").lower()
            in {"1", "yes", "true", "on"}
        ),
    )
    if reasons:
        raise StudyError(
            "native timing is allowed only on an x86_64 Fedora host outside "
            "containers and Apple-hosted emulation: "
            + "; ".join(reasons)
        )


def _read_build_id(executable: Path) -> dict[str, Any]:
    readelf = command_path("readelf")
    if not readelf:
        return {"status": "unavailable", "reason": "readelf is missing", "value": None}
    result = run_command([readelf, "-n", str(executable)], check=False, timeout=30)
    match = re.search(r"Build ID:\s*([0-9a-fA-F]+)", result.stdout + result.stderr)
    return {
        "status": "observed" if match else "not-present",
        "reason": None if match else "ELF note did not expose a build ID",
        "value": match.group(1).lower() if match else None,
        "raw": result.stdout + result.stderr,
    }


def _linked_packages(executable: Path) -> dict[str, Any]:
    ldd = command_path("ldd")
    rpm = command_path("rpm")
    if not ldd:
        return {
            "status": "unavailable", "complete": False,
            "problems": ["ldd is missing"], "raw": "", "packages": [],
        }
    result = run_command([ldd, str(executable)], check=False, timeout=30)
    paths = sorted(set(re.findall(r"(?:=>\s+)?(/[^\s(]+)", result.stdout)))
    packages: list[dict[str, Any]] = []
    for path in paths:
        if rpm and Path(path).exists():
            owner = run_command([rpm, "-qf", path], check=False, timeout=15)
            packages.append({
                "path": path,
                "sha256": sha256_file(Path(path)),
                "owner": owner.stdout.strip() if owner.returncode == 0 else None,
                "owner_query_returncode": owner.returncode,
            })
        else:
            packages.append({
                "path": path,
                "sha256": sha256_file(Path(path)) if Path(path).is_file() else None,
                "owner": None,
                "owner_query_returncode": None,
            })
    problems: list[str] = []
    if result.returncode != 0:
        problems.append(f"ldd returned {result.returncode}")
    if not packages:
        problems.append("ldd exposed no absolute linked-library paths")
    for item in packages:
        if not item.get("sha256"):
            problems.append(f"linked path is unavailable: {item.get('path')}")
        if item.get("owner_query_returncode") != 0 or not item.get("owner"):
            problems.append(f"linked path has no proved RPM owner: {item.get('path')}")
    return {
        "status": "observed" if result.returncode == 0 else "failed",
        "complete": not problems,
        "problems": problems,
        "ldd_returncode": result.returncode,
        "raw": result.stdout + result.stderr,
        "packages": packages,
    }


def _dirsrv_runtime_lock_metadata(
        path: Path = DIRSRV_RUNTIME_LOCK_PATH) -> dict[str, Any]:
    """Describe the shared lock directory normally changed by ``dscreate``."""
    try:
        metadata = path.lstat()
        owner = pwd.getpwuid(metadata.st_uid).pw_name
        group = grp.getgrgid(metadata.st_gid).gr_name
    except (KeyError, OSError) as error:
        return {
            "status": "unavailable",
            "path": str(path),
            "reason": str(error),
        }
    return {
        "status": "observed",
        "path": str(path),
        "is_directory": stat.S_ISDIR(metadata.st_mode),
        "is_symlink": stat.S_ISLNK(metadata.st_mode),
        "mode": format(stat.S_IMODE(metadata.st_mode), "04o"),
        "owner": owner,
        "group": group,
    }


def rpm_verify_evidence(
        executable_name: str, *, returncode: int, stdout: str, stderr: str,
        runtime_lock_metadata: Mapping[str, Any] | None = None,
        ) -> dict[str, Any]:
    """Classify strict RPM verification and one normal 389 DS runtime delta.

    Creating a 389 DS instance changes the RPM-owned ghost directory
    ``/var/lock/dirsrv`` from its package-build owner to ``dirsrv:dirsrv``.
    Instance removal intentionally leaves the shared parent in that usable
    runtime state.  Accept only that exact owner/group-only ghost difference;
    every content, mode, executable, library, or additional path difference
    remains fatal and timing-ineligible.
    """
    lines = [
        line.strip()
        for text in (stdout, stderr)
        for line in text.splitlines()
        if line.strip()
    ]
    parsed: list[dict[str, str | None]] = []
    unparsed: list[str] = []
    for line in lines:
        match = RPM_VERIFY_LINE.fullmatch(line)
        if match is None:
            unparsed.append(line)
            continue
        parsed.append({
            "flags": match.group("flags"),
            "file_type": match.group("file_type"),
            "path": match.group("path"),
        })

    clean = returncode == 0
    lock = dict(runtime_lock_metadata or {})
    allowed_runtime_ghost = (
        executable_name == "ns-slapd"
        and returncode == 1
        and not unparsed
        and parsed == [{
            "flags": DIRSRV_RUNTIME_LOCK_VERIFY_FLAGS,
            "file_type": "g",
            "path": str(DIRSRV_RUNTIME_LOCK_PATH),
        }]
        and lock.get("status") == "observed"
        and lock.get("path") == str(DIRSRV_RUNTIME_LOCK_PATH)
        and lock.get("is_directory") is True
        and lock.get("is_symlink") is False
        and lock.get("mode") == "0770"
        and lock.get("owner") == "dirsrv"
        and lock.get("group") == "dirsrv"
    )
    return {
        "returncode": returncode,
        "stdout": stdout,
        "stderr": stderr,
        "clean": clean,
        "accepted": clean or allowed_runtime_ghost,
        "acceptance_policy": (
            "strict-clean-or-dirsrv-runtime-lock-ghost-ownership-v1"
        ),
        "accepted_via_runtime_ghost_allowlist": allowed_runtime_ghost,
        "allowed_differences": parsed if allowed_runtime_ghost else [],
        "unexpected_differences": (
            [] if clean or allowed_runtime_ghost else lines
        ),
        "runtime_lock_metadata": lock or None,
    }


def rpm_source_identity_evidence(
    expected_source_sha: str, git_tokens: Sequence[str]
) -> dict[str, Any]:
    """Classify how strongly RPM metadata establishes source identity.

    A short ``git<sha>`` token is useful corroboration, but it is not an
    independent proof of the operator-supplied 40-character revision.  Only
    an exact full-length token can establish that stronger claim.
    """
    expected = expected_source_sha.casefold()
    normalized = sorted({token.casefold() for token in git_tokens})
    if not re.fullmatch(r"[0-9a-f]{40}", expected):
        return {
            "source_identity_basis": "operator-assertion",
            "source_metadata_git_tokens": normalized,
            "source_metadata_exact_git_tokens": [],
            "source_identity_prefix_verified": False,
            "source_identity_independently_proved": False,
        }
    mismatches = [
        token for token in normalized
        if not expected.startswith(token) and not token.startswith(expected)
    ]
    if mismatches:
        raise StudyError(
            f"installed RPM metadata identifies git {', '.join(mismatches)}, "
            f"not operator-expected {expected_source_sha}"
        )
    exact_tokens = [
        token for token in normalized
        if len(token) == 40 and token == expected
    ]
    prefix_verified = bool(normalized) and not mismatches
    return {
        "source_identity_basis": (
            "package-metadata-full-sha"
            if exact_tokens
            else "package-metadata-prefix-plus-operator-assertion"
            if prefix_verified
            else "operator-assertion"
        ),
        "source_metadata_git_tokens": normalized,
        "source_metadata_exact_git_tokens": exact_tokens,
        "source_identity_prefix_verified": prefix_verified,
        "source_identity_independently_proved": bool(exact_tokens),
    }


def installed_rpm_identity(
    executable_name: str,
    *,
    expected_source_sha: str,
    fail_on_verify: bool,
    require_complete_389_closure: bool = False,
) -> dict[str, Any]:
    paths = require_commands([executable_name, "rpm"])
    executable = Path(paths[executable_name])
    rpm = paths["rpm"]
    owner_result = run_command([rpm, "-qf", str(executable)], timeout=30)
    owner = owner_result.stdout.strip().splitlines()[0]
    nevra_result = run_command(
        [rpm, "-q", "--qf", "%{NEVRA}\\n", owner], timeout=30
    )
    nevra = nevra_result.stdout.strip()
    query_info = run_command([rpm, "-qi", owner], timeout=30).stdout
    verify = run_command([rpm, "-V", owner], check=False, timeout=120)
    runtime_lock_metadata = (
        _dirsrv_runtime_lock_metadata()
        if executable_name == "ns-slapd" and verify.returncode != 0
        else None
    )
    verify_evidence = rpm_verify_evidence(
        executable_name,
        returncode=verify.returncode,
        stdout=verify.stdout,
        stderr=verify.stderr,
        runtime_lock_metadata=runtime_lock_metadata,
    )
    if fail_on_verify and verify_evidence["accepted"] is not True:
        detail = verify.stdout.strip() or verify.stderr.strip() or "rpm -V returned no details"
        raise StudyError(f"RPM verification failed for {owner}: {detail}")

    git_tokens = sorted(set(re.findall(r"(?i)git([0-9a-f]{7,40})", nevra + "\n" + query_info)))
    source_evidence = rpm_source_identity_evidence(
        expected_source_sha, git_tokens,
    )
    linked = _linked_packages(executable)
    package_closure: list[dict[str, Any]] = []
    if executable_name == "ns-slapd":
        closure_names = [
            "389-ds-base", "389-ds-base-libs", "python3-lib389",
        ]
        robdb_query = run_command(
            [rpm, "-q", "389-ds-base-robdb-libs"],
            check=False, timeout=30,
        )
        if require_complete_389_closure or robdb_query.returncode == 0:
            closure_names.insert(2, "389-ds-base-robdb-libs")
        for package_name in closure_names:
            query = run_command(
                [
                    rpm, "-q", "--qf",
                    "%{NEVRA}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t"
                    "%{SOURCERPM}\n",
                    package_name,
                ],
                timeout=30,
            )
            fields = query.stdout.rstrip("\n").split("\t")
            if len(fields) != 3 or any(not field for field in fields):
                raise StudyError(
                    f"could not establish package closure identity for "
                    f"{package_name}"
                )
            package_verify = run_command(
                [rpm, "-V", package_name], check=False, timeout=120,
            )
            if package_name == "389-ds-base":
                verification = verify_evidence
            else:
                verification = {
                    "returncode": package_verify.returncode,
                    "stdout": package_verify.stdout,
                    "stderr": package_verify.stderr,
                    "clean": package_verify.returncode == 0
                    and not package_verify.stdout.strip()
                    and not package_verify.stderr.strip(),
                    "accepted": package_verify.returncode == 0
                    and not package_verify.stdout.strip()
                    and not package_verify.stderr.strip(),
                    "acceptance_policy": "strict-clean-v1",
                }
            if fail_on_verify and verification["accepted"] is not True:
                detail = (
                    package_verify.stdout.strip()
                    or package_verify.stderr.strip()
                    or "rpm -V returned no details"
                )
                raise StudyError(
                    f"RPM verification failed for {package_name}: {detail}"
                )
            package_closure.append({
                "package_name": package_name,
                "nevra": fields[0],
                "epoch_version_release": fields[1],
                "source_rpm": fields[2],
                "rpm_verify": verification,
            })
        evrs = {
            record["epoch_version_release"] for record in package_closure
        }
        source_rpms = {record["source_rpm"] for record in package_closure}
        if len(evrs) != 1 or len(source_rpms) != 1:
            raise StudyError(
                "389 DS package closure is mixed: every captured companion "
                "package must have one EVR and source RPM"
            )
    executable_sha256 = sha256_file(executable)
    closure_artifacts = [{
        "sha256": executable_sha256,
        "roles": ["server-executable"],
    }]
    closure_artifacts.extend({
        "sha256": item["sha256"],
        "roles": ["direct-linked-library"],
    } for item in linked.get("packages", []) if item.get("sha256"))
    closure_material = {
        "format_version": 1,
        "artifacts": sorted(
            closure_artifacts,
            key=lambda item: (item["roles"], item["sha256"]),
        ),
    }
    sanitizer_libraries = [
        item["path"]
        for item in linked.get("packages", [])
        if re.search(r"lib(?:a|l|t|ub)san", Path(item["path"]).name, re.I)
    ]
    return {
        "executable_name": executable_name,
        "executable_path": str(executable),
        "executable_sha256": executable_sha256,
        "elf_build_id": _read_build_id(executable),
        "owning_package": owner,
        "package_nevra": nevra,
        "rpm_query_info": query_info,
        "rpm_verify": verify_evidence,
        "linked_libraries": linked,
        "installed_package_closure": {
            "format_version": 1,
            "required_packages": [
                record["package_name"] for record in package_closure
            ],
            "packages": package_closure,
            "complete": bool(package_closure),
            "native_four_package_required": (
                executable_name == "ns-slapd"
                and require_complete_389_closure
            ),
        },
        "runtime_closure_sha256": sha256_bytes(
            json.dumps(
                closure_material, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")
        ),
        "runtime_closure_identity_material": closure_material,
        "sanitizer_libraries": sanitizer_libraries,
        "unsanitized": not sanitizer_libraries,
        "expected_source_sha": expected_source_sha,
        **source_evidence,
    }


_PROC_MAP_LINE = re.compile(
    r"^[0-9a-fA-F]+-[0-9a-fA-F]+\s+(\S+)\s+\S+\s+\S+\s+\d+\s*(.*)$"
)


def _decode_proc_map_path(value: str) -> str:
    """Decode the octal path escapes used by Linux /proc/PID/maps."""
    return re.sub(
        r"\\([0-7]{3})",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )


def backend_module_roles(
        path: Path, *, server: str, backend: str) -> list[str]:
    name = path.name.casefold()
    roles: set[str] = set()
    if server == "389ds" and re.fullmatch(
            r"libback-ldbm\.so(?:\.[0-9]+)*", name):
        roles.add("389ds-ldbm-backend")
    if backend == "mdb":
        if server == "389ds" and re.fullmatch(
                r"libdb-mdb\.so(?:\.[0-9]+)*", name):
            roles.add("389ds-db-adapter")
        if server == "openldap" and re.fullmatch(
                r"back_mdb(?:-\d+(?:\.\d+)*)?\.so(?:\.[0-9]+)*", name):
            roles.add("openldap-db-backend")
        if re.fullmatch(r"liblmdb\.so(?:\.[0-9]+)*", name):
            roles.add("database-engine")
    elif backend == "bdb":
        if server == "389ds" and re.fullmatch(
                r"libdb-bdb\.so(?:\.[0-9]+)*", name):
            roles.add("389ds-db-adapter")
        if server == "openldap" and re.fullmatch(
                r"back_(?:bdb|hdb)(?:-\d+(?:\.\d+)*)?\.so(?:\.[0-9]+)*",
                name):
            roles.add("openldap-db-backend")
        if re.fullmatch(
                r"libdb(?:-\d+(?:\.\d+)*)?\.so(?:\.[0-9]+)*", name):
            roles.add("database-engine")
    return sorted(roles)


def parse_openldap_static_backends(inventory: str) -> list[str]:
    """Parse the one contiguous, indented backend list emitted by slapd -VVV."""
    marker = "Included static backends:"
    lines = inventory.splitlines()
    marker_indexes = [index for index, line in enumerate(lines) if line == marker]
    if len(marker_indexes) != 1:
        raise ValueError("static backend inventory must contain one exact marker line")
    backends: list[str] = []
    for line in lines[marker_indexes[0] + 1:]:
        match = re.fullmatch(r"[ \t]+([A-Za-z0-9_-]+)[ \t]*", line)
        if not match:
            break
        backends.append(match.group(1).casefold())
    if not backends or len(backends) != len(set(backends)):
        raise ValueError("static backend inventory list is empty or duplicated")
    return sorted(backends)


def backend_runtime_module_closure(
        pid: int, *, server: str, backend: str,
        maps_path: Path | None = None,
        rpm_command: str | None = None,
        require_rpm_owner: bool = True,
        live_executable_path: Path | None = None,
        expected_executable_path: Path | None = None,
        expected_executable_sha256: str | None = None) -> dict[str, Any]:
    """Capture the loaded backend module identity from Linux proc maps.

    Address ranges, permissions, offsets, map order, paths, and RPM ownership
    are intentionally not identity inputs.  Paths and owners remain recorded
    provenance, while the deterministic digest covers the live executable,
    selected server/backend, required roles, and each module's content hash and
    semantic role.  This catches dlopened LDBM/DB plugins that an executable
    ``ldd`` snapshot cannot see.
    """
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise StudyError("backend runtime closure requires a positive server pid")
    server_name = server.casefold()
    backend_name = backend.casefold()
    if server_name not in {"389ds", "openldap"}:
        raise StudyError(f"unsupported server for runtime closure: {server}")
    if backend_name not in {"mdb", "bdb"}:
        raise StudyError(f"unsupported backend for runtime closure: {backend}")
    proc_maps = maps_path or Path(f"/proc/{pid}/maps")
    try:
        maps_text = proc_maps.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        raise StudyError(f"cannot read live server mappings {proc_maps}: {error}") from error

    proc_executable = live_executable_path or Path(f"/proc/{pid}/exe")
    try:
        resolved_executable = proc_executable.resolve(strict=True)
    except OSError as error:
        raise StudyError(
            f"cannot resolve live server executable {proc_executable}: {error}"
        ) from error
    if not resolved_executable.is_file():
        raise StudyError(
            f"live server executable is not a regular file: {resolved_executable}"
        )
    live_executable_sha256 = sha256_file(resolved_executable)
    if expected_executable_path is not None:
        try:
            resolved_expected = expected_executable_path.resolve(strict=True)
        except OSError as error:
            raise StudyError(
                f"cannot resolve expected server executable {expected_executable_path}: {error}"
            ) from error
        if resolved_expected != resolved_executable:
            raise StudyError(
                "live server PID belongs to a different executable: "
                f"{resolved_executable} != {resolved_expected}"
            )
    if expected_executable_sha256 is not None:
        if (
                not re.fullmatch(r"[0-9a-f]{64}", expected_executable_sha256)
                or live_executable_sha256 != expected_executable_sha256):
            raise StudyError(
                "live server executable hash differs from installed-artifact identity"
            )

    selected: dict[str, dict[str, Any]] = {}
    for line in maps_text.splitlines():
        match = _PROC_MAP_LINE.match(line)
        if not match:
            continue
        permissions = match.group(1)
        if "x" not in permissions:
            continue
        mapped = _decode_proc_map_path(match.group(2).strip())
        if not mapped.startswith("/"):
            continue
        deleted = mapped.endswith(" (deleted)")
        disk_path_text = mapped[:-10] if deleted else mapped
        disk_path = Path(disk_path_text)
        roles = backend_module_roles(
            disk_path, server=server_name, backend=backend_name,
        )
        if not roles:
            continue
        if deleted:
            raise StudyError(
                f"loaded backend module was deleted and cannot be identified: {disk_path}"
            )
        try:
            resolved = disk_path.resolve(strict=True)
        except OSError as error:
            raise StudyError(
                f"loaded backend module cannot be resolved: {disk_path}: {error}"
            ) from error
        if not resolved.is_file():
            raise StudyError(f"loaded backend module is not a file: {resolved}")
        key = str(resolved)
        record = selected.setdefault(key, {
            "path": key,
            "mapped_paths": set(),
            "roles": set(),
        })
        record["mapped_paths"].add(disk_path_text)
        record["roles"].update(roles)

    required_roles = {"database-engine"}
    required_roles.add(
        "389ds-ldbm-backend" if server_name == "389ds"
        else "openldap-db-backend"
    )
    observed_roles = {
        role for record in selected.values() for role in record["roles"]
    }
    missing_roles = required_roles.difference(observed_roles)
    static_backend_evidence: dict[str, Any] | None = None
    if missing_roles and server_name == "openldap" and backend_name == "mdb":
        if not resolved_executable.is_file() or resolved_executable.name != "slapd":
            raise StudyError(
                "live OpenLDAP executable is not a regular slapd binary: "
                f"{resolved_executable}"
            )
        inventory = run_command(
            [str(resolved_executable), "-VVV"], check=False, timeout=30,
        )
        inventory_text = inventory.stdout + inventory.stderr
        if inventory.returncode != 0:
            detail = inventory_text.strip() or "no backend inventory output"
            raise StudyError(
                "could not prove OpenLDAP's built-in backend inventory: " + detail
            )
        try:
            included_static_backends = parse_openldap_static_backends(
                inventory_text
            )
        except ValueError as error:
            raise StudyError(
                "could not prove OpenLDAP's built-in backend inventory: "
                f"{error}"
            ) from error
        if backend_name not in included_static_backends:
            raise StudyError(
                f"live slapd does not report {backend_name} as an included static backend"
            )
        key = str(resolved_executable)
        record = selected.setdefault(key, {
            "path": key,
            "mapped_paths": set(),
            "roles": set(),
        })
        record["mapped_paths"].add(f"/proc/{pid}/exe")
        assigned_roles = sorted(missing_roles)
        record["roles"].update(assigned_roles)
        static_backend_evidence = {
            "status": "observed",
            "source": "slapd--VVV",
            "live_executable": key,
            "included_static_backends": included_static_backends,
            "selected_backend": backend_name,
            "assigned_roles": assigned_roles,
            "inventory_sha256": sha256_bytes(inventory_text.encode("utf-8")),
            "raw": inventory_text,
        }
        observed_roles = {
            role for selected_record in selected.values()
            for role in selected_record["roles"]
        }
        missing_roles = required_roles.difference(observed_roles)
    if missing_roles:
        raise StudyError(
            "live server mappings omit required backend runtime role(s): "
            + ", ".join(sorted(missing_roles))
        )

    rpm = rpm_command or command_path("rpm")
    if require_rpm_owner and not rpm:
        raise StudyError("rpm is required to own loaded backend runtime modules")
    modules: list[dict[str, Any]] = []
    for path_text in sorted(selected):
        record = selected[path_text]
        owner = None
        owner_returncode = None
        if rpm:
            owner_result = run_command(
                [rpm, "-qf", path_text], check=False, timeout=30,
            )
            owner_returncode = owner_result.returncode
            if owner_result.returncode == 0 and owner_result.stdout.strip():
                owner = owner_result.stdout.strip().splitlines()[0]
        if require_rpm_owner and owner is None:
            raise StudyError(f"loaded backend module has no RPM owner: {path_text}")
        modules.append({
            "path": path_text,
            "mapped_paths": sorted(record["mapped_paths"]),
            "sha256": sha256_file(Path(path_text)),
            "rpm_owner": owner,
            "rpm_owner_query_returncode": owner_returncode,
            "roles": sorted(record["roles"]),
        })

    identity_modules = [{
        "sha256": module["sha256"],
        "roles": module["roles"],
    } for module in modules]
    identity_material = {
        "format_version": 1,
        "server": server_name,
        "backend": backend_name,
        "required_roles": sorted(required_roles),
        "live_executable_sha256": live_executable_sha256,
        "modules": sorted(
            identity_modules,
            key=lambda module: (module["roles"], module["sha256"]),
        ),
    }
    return {
        "format_version": 1,
        "status": "observed",
        "source": "linux-proc-pid-maps",
        "pid": pid,
        "maps_path": str(proc_maps),
        "server": server_name,
        "backend": backend_name,
        "live_executable": {
            "path": str(resolved_executable),
            "sha256": live_executable_sha256,
            "proc_exe_path": f"/proc/{pid}/exe",
        },
        "required_roles": sorted(required_roles),
        "modules": modules,
        "static_backend_evidence": static_backend_evidence,
        "identity_material": identity_material,
        "identity_sha256": sha256_bytes(
            json.dumps(
                identity_material, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")
        ),
    }


def combined_behavioral_runtime_identity(
        runtime_closure_sha256: str,
        backend_runtime_closure_sha256: str) -> str:
    """Combine direct-link and live backend closures into one behavior ID."""
    for label, value in (
            ("runtime_closure_sha256", runtime_closure_sha256),
            ("backend_runtime_closure_sha256", backend_runtime_closure_sha256)):
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise StudyError(f"{label} is not a lowercase SHA-256")
    material = {
        "format_version": 1,
        "runtime_closure_sha256": runtime_closure_sha256,
        "backend_runtime_closure_sha256": backend_runtime_closure_sha256,
    }
    return sha256_bytes(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def process_metrics(
        pid: int, *, proc_root: Path = Path("/proc")) -> dict[str, Any]:
    """Snapshot process CPU and memory with nanosecond CPU accounting.

    Linux exposes per-thread scheduled runtime in ``task/*/schedstat``.  The
    sum is the high-resolution whole-process CPU clock used for measurements.
    Traditional process ticks remain in the result solely as an audit trail.
    """
    process_root = proc_root / str(pid)
    stat_text = read_text(process_root / "stat")
    status_text = read_text(process_root / "status")
    ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"]) if stat_text else 100
    user_ticks = system_ticks = None
    if stat_text:
        # The command name may contain spaces and parentheses; fields after the
        # final ')' begin with the canonical field 3 (state).
        tail = stat_text.rsplit(")", 1)[-1].strip().split()
        if len(tail) >= 13:
            user_ticks = int(tail[11])
            system_ticks = int(tail[12])

    schedstat_total = 0
    schedstat_read = 0
    schedstat_warnings: list[str] = []
    task_root = process_root / "task"
    try:
        tasks = sorted(
            (path for path in task_root.iterdir() if path.name.isdigit()),
            key=lambda path: int(path.name),
        )
    except OSError as error:
        tasks = []
        schedstat_warnings.append(str(error))
    for task in tasks:
        try:
            fields = (task / "schedstat").read_text(
                encoding="ascii", errors="strict",
            ).split()
        except OSError as error:
            schedstat_warnings.append(f"task {task.name}: {error}")
            continue
        if not fields or not fields[0].isdigit():
            schedstat_warnings.append(f"task {task.name}: invalid schedstat")
            continue
        schedstat_total += int(fields[0])
        schedstat_read += 1
    schedstat_complete = bool(tasks) and schedstat_read == len(tasks)

    def status_kib(name: str) -> int | None:
        match = re.search(rf"^{re.escape(name)}:\s+(\d+)\s+kB", status_text, re.M)
        return int(match.group(1)) if match else None

    return {
        "pid": pid,
        "cpu_clock_source": "linux-proc-task-schedstat",
        "schedstat_runtime_ns": schedstat_total if schedstat_complete else None,
        "schedstat_partial_runtime_ns": schedstat_total,
        "schedstat_task_count": len(tasks),
        "schedstat_tasks_read": schedstat_read,
        "schedstat_complete": schedstat_complete,
        "schedstat_warnings": schedstat_warnings,
        "clock_ticks_per_second": ticks,
        "user_cpu_ticks": user_ticks,
        "system_cpu_ticks": system_ticks,
        "user_cpu_seconds": (
            user_ticks / ticks if user_ticks is not None else None
        ),
        "system_cpu_seconds": (
            system_ticks / ticks if system_ticks is not None else None
        ),
        "rss_kib": status_kib("VmRSS"),
        "high_water_kib": status_kib("VmHWM"),
    }


def metric_delta(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "cpu_clock_source": "linux-proc-task-schedstat",
        "schedstat_before_task_count": before.get("schedstat_task_count"),
        "schedstat_after_task_count": after.get("schedstat_task_count"),
        "schedstat_before_complete": before.get("schedstat_complete"),
        "schedstat_after_complete": after.get("schedstat_complete"),
        "clock_ticks_per_second": after.get("clock_ticks_per_second"),
    }
    runtime_before = before.get("schedstat_runtime_ns")
    runtime_after = after.get("schedstat_runtime_ns")
    runtime_delta = None
    if isinstance(runtime_before, int) and isinstance(runtime_after, int):
        if runtime_after < runtime_before:
            raise StudyError("process schedstat runtime moved backwards")
        runtime_delta = runtime_after - runtime_before
    result["server_cpu_ns"] = runtime_delta
    result["server_cpu_seconds"] = (
        runtime_delta / 1_000_000_000 if runtime_delta is not None else None
    )
    for key in ("user_cpu_seconds", "system_cpu_seconds"):
        left, right = before.get(key), after.get(key)
        result[key] = right - left if left is not None and right is not None else None
    for key in ("user_cpu_ticks", "system_cpu_ticks"):
        left, right = before.get(key), after.get(key)
        if isinstance(left, int) and isinstance(right, int):
            if right < left:
                raise StudyError(f"process {key} moved backwards")
            result[key] = right - left
        else:
            result[key] = None
    result["rss_kib"] = after.get("rss_kib")
    result["high_water_kib"] = after.get("high_water_kib")
    return result
