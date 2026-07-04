# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2026 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---

import errno
import json
import mmap
import os
import stat
import struct
import time

import psutil

from lib389._constants import DN_CONFIG
from lib389.cli_base import CustomHelpFormatter
from lib389.dseldif import DSEldif


TP_STATS_MAGIC = 0x54504f4f4c535431
TP_STATS_VER_MAJOR = 1
TP_STATS_HEADER_SIZE = 4096
TP_STATS_WORKER_SLOT_SIZE = 640
TP_STATS_STALE_NS = 30 * 1000 * 1000 * 1000
TP_STATS_MONO_IMPLAUSIBLE_NS = 365 * 24 * 60 * 60 * 1000 * 1000 * 1000

HEADER_FORMAT = "@QHHIIIQQQQIIQQQQQQQ"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
WORKER_HEAD_FORMAT = "@IIQQQ"

STATE_NAMES = {
    0: "unused",
    1: "idle",
    2: "busy",
    3: "exited",
}

OP_NAMES = {
    0x60: "bind",
    0x42: "unbind",
    0x63: "search",
    0x66: "modify",
    0x68: "add",
    0x4A: "delete",
    0x6C: "modrdn",
    0x6E: "compare",
    0x50: "abandon",
    0x77: "extended",
}


def _server_file_prefix(serverid):
    if serverid.startswith("slapd-"):
        return serverid
    return f"slapd-{serverid}"


def _resolve_threadpool_path(inst):
    warnings = []
    dse = DSEldif(inst)
    rundir = dse.get(DN_CONFIG, "nsslapd-rundir", single=True, lower=True)
    if rundir is None:
        rundir = inst.ds_paths.run_dir
        warnings.append("nsslapd-rundir is missing from dse.ldif; using lib389 run_dir fallback")
    return os.path.join(rundir, f"{_server_file_prefix(inst.serverid)}.threadpool"), warnings, dse


def _config_threadnumber(dse):
    value = dse.get(DN_CONFIG, "nsslapd-threadnumber", single=True, lower=True)
    if value is None:
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed > 0 else None


def _config_tp_stats_enabled(dse):
    value = dse.get(DN_CONFIG, "nsslapd-thread-pool-stats", single=True, lower=True)
    if value is None:
        return True
    return value.lower() != "off"


def _open_threadpool_file(path, inst, tp_stats_enabled):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        if inst.status():
            if not tp_stats_enabled:
                raise ValueError(
                    "thread-pool status is disabled by nsslapd-thread-pool-stats in cn=config"
                )
            raise ValueError(
                "server is running but the thread-pool status file is missing "
                "(initialization may have failed - check the errors log; "
                "or the server predates this feature, or nsslapd-rundir mismatch)"
            )
        raise ValueError("instance is not running (status file is removed on clean shutdown)")
    except PermissionError:
        raise ValueError("permission denied; run as root or a member of the dirsrv group")
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise ValueError("refusing to read thread-pool status through a symlink")
        raise

    return fd


def _validate_stat(path, st):
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"refusing to read non-regular thread-pool status file: {path}")
    if st.st_size < TP_STATS_HEADER_SIZE:
        raise ValueError(
            f"thread-pool status file is too short: {st.st_size} bytes "
            f"(expected at least {TP_STATS_HEADER_SIZE})"
        )


def _unpack_header(mm):
    if len(mm) < HEADER_SIZE:
        raise ValueError("thread-pool status header is truncated")

    fields = struct.unpack_from(HEADER_FORMAT, mm, 0)
    header = {
        "magic": fields[0],
        "ver_major": fields[1],
        "ver_minor": fields[2],
        "header_size": fields[3],
        "worker_slot_size": fields[4],
        "max_workers": fields[5],
        "server_pid": fields[6],
        "start_wall_sec": fields[7],
        "heartbeat_mono_ns": fields[8],
        "heartbeat_wall_sec": fields[9],
        "shutdown_clean": fields[10],
        "cur_work_queue": fields[12],
        "max_work_queue": fields[13],
        "cur_busy_workers": fields[14],
        "max_busy_workers": fields[15],
        "ops_initiated": fields[16],
        "ops_completed": fields[17],
        "cur_connections": fields[18],
    }

    if header["magic"] != TP_STATS_MAGIC:
        raise ValueError("bad thread-pool status magic; refusing to parse file")
    if header["ver_major"] != TP_STATS_VER_MAJOR:
        raise ValueError(
            f"unsupported thread-pool status version "
            f"{header['ver_major']}.{header['ver_minor']}"
        )
    if header["header_size"] != TP_STATS_HEADER_SIZE:
        raise ValueError(
            f"unsupported thread-pool status header size {header['header_size']}"
        )
    if header["worker_slot_size"] != TP_STATS_WORKER_SLOT_SIZE:
        raise ValueError(
            f"unsupported thread-pool worker slot size {header['worker_slot_size']}"
        )
    if header["max_workers"] < 1 or header["max_workers"] > 65535:
        raise ValueError(f"invalid thread-pool worker count {header['max_workers']}")

    expected_size = header["header_size"] + (header["max_workers"] * header["worker_slot_size"])
    if expected_size > len(mm):
        raise ValueError(
            f"thread-pool status file is truncated: {len(mm)} bytes "
            f"(expected at least {expected_size})"
        )

    return header


def _state_name(state):
    return STATE_NAMES.get(state, f"unknown-{state}")


def _op_name(op_tag):
    if op_tag == 0:
        return ""
    return OP_NAMES.get(op_tag, str(op_tag))


def _duration_ns(now_ns, start_ns, op_id):
    if op_id == 0 or start_ns == 0:
        return 0
    if now_ns < start_ns:
        return 0
    return now_ns - start_ns


def _unpack_workers(mm, header, now_ns):
    workers = []
    for idx in range(header["max_workers"]):
        offset = header["header_size"] + (idx * header["worker_slot_size"])
        state, op_tag, conn_id, op_id, start_ns = struct.unpack_from(WORKER_HEAD_FORMAT, mm, offset)
        if state == 0:
            continue
        workers.append({
            "idx": idx + 1,
            "state": _state_name(state),
            "op": _op_name(op_tag),
            "conn": conn_id if conn_id != 0 else None,
            "op_id": op_id if op_id != 0 else None,
            "duration_ns": _duration_ns(now_ns, start_ns, op_id),
        })
    return workers


def _pid_warnings(pid):
    """Return (warnings, pid_alive); pid_alive means a live ns-slapd owns the pid"""
    warnings = []
    if pid == 0:
        warnings.append("status file does not contain a valid server pid")
        return warnings, False

    if not psutil.pid_exists(pid):
        warnings.append(f"stale file from a crashed or killed server (pid {pid} is not running)")
        return warnings, False

    try:
        name = psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        warnings.append(f"stale file from a crashed or killed server (pid {pid} is not running)")
        return warnings, False
    except psutil.AccessDenied:
        warnings.append(f"server pid {pid} exists but process name could not be inspected")
        return warnings, True

    if name != "ns-slapd":
        warnings.append(f"stale file: pid {pid} belongs to {name!r}, not 'ns-slapd'")
        return warnings, False
    return warnings, True


def _heartbeat_age(now_ns, heartbeat_ns):
    if heartbeat_ns == 0:
        return None
    return now_ns - heartbeat_ns


def _heartbeat_warnings(pid_alive, age_ns):
    warnings = []
    if age_ns is None:
        warnings.append("thread-pool heartbeat has never been written")
    elif age_ns < 0:
        warnings.append("thread-pool heartbeat is from a different monotonic-clock domain")
    elif age_ns > TP_STATS_MONO_IMPLAUSIBLE_NS:
        warnings.append("thread-pool heartbeat age is implausible; the file may predate a reboot")
    elif age_ns > TP_STATS_STALE_NS:
        if pid_alive:
            warnings.append("server process exists but diagnostics are stale; server may be stalled")
        else:
            warnings.append("thread-pool diagnostics are stale")
    return warnings


def _read_threadpool_status(inst):
    path, warnings, dse = _resolve_threadpool_path(inst)
    configured_threads = _config_threadnumber(dse)
    tp_stats_enabled = _config_tp_stats_enabled(dse)
    fd = _open_threadpool_file(path, inst, tp_stats_enabled)
    try:
        st = os.fstat(fd)
        _validate_stat(path, st)
        with mmap.mmap(fd, 0, access=mmap.ACCESS_READ) as mm:
            header = _unpack_header(mm)
            now_ns = time.monotonic_ns()
            age_ns = _heartbeat_age(now_ns, header["heartbeat_mono_ns"])
            pid_warnings, pid_alive = _pid_warnings(header["server_pid"])
            warnings.extend(pid_warnings)
            warnings.extend(_heartbeat_warnings(pid_alive, age_ns))

            if header["shutdown_clean"] != 0:
                warnings.append("clean shutdown leftover")
            if configured_threads is not None and configured_threads != header["max_workers"]:
                warnings.append(
                    f"dse.ldif nsslapd-threadnumber is {configured_threads}, "
                    f"but status file was sized for {header['max_workers']} workers"
                )

            workers = _unpack_workers(mm, header, now_ns)
    finally:
        os.close(fd)

    age_sec = None if age_ns is None else age_ns / 1_000_000_000
    start_wall = header["start_wall_sec"]
    uptime_sec = max(0, int(time.time()) - start_wall) if start_wall else None

    return {
        "type": "result",
        "instance": inst.serverid,
        "path": path,
        "pid": header["server_pid"],
        "version": {
            "major": header["ver_major"],
            "minor": header["ver_minor"],
        },
        "start_wall_sec": start_wall,
        "uptime_sec": uptime_sec,
        "heartbeat_age_sec": age_sec,
        "heartbeat_wall_sec": header["heartbeat_wall_sec"],
        "pool": {
            "max_workers": header["max_workers"],
            "cur_busy_workers": header["cur_busy_workers"],
            "max_busy_workers": header["max_busy_workers"],
            "cur_work_queue": header["cur_work_queue"],
            "max_work_queue": header["max_work_queue"],
            "ops_initiated": header["ops_initiated"],
            "ops_completed": header["ops_completed"],
            "cur_connections": header["cur_connections"],
        },
        "workers": workers,
        "warnings": warnings,
    }


def _format_seconds(value):
    if value is None:
        return "unknown"
    return f"{value:.3f}s"


def _format_duration_ns(duration_ns):
    if duration_ns == 0:
        return "-"
    seconds = duration_ns / 1_000_000_000
    if seconds < 1:
        return f"{seconds * 1000:.1f}ms"
    return f"{seconds:.3f}s"


def _format_optional(value):
    return "-" if value is None else str(value)


def _emit_text(log, status):
    pool = status["pool"]
    log.info(f"Instance: {status['instance']}")
    log.info(f"Path: {status['path']}")
    log.info(f"PID: {status['pid']}")
    log.info(f"Uptime: {_format_seconds(status['uptime_sec'])}")
    log.info(f"Heartbeat age: {_format_seconds(status['heartbeat_age_sec'])}")
    log.info(
        "Workers: "
        f"{pool['cur_busy_workers']}/{pool['max_workers']} busy "
        f"(max {pool['max_busy_workers']})"
    )
    log.info(
        "Queue: "
        f"{pool['cur_work_queue']} current "
        f"(max {pool['max_work_queue']})"
    )
    log.info(
        "Operations: "
        f"{pool['ops_initiated']} initiated, "
        f"{pool['ops_completed']} completed"
    )
    log.info(f"Current connections: {pool['cur_connections']}")

    if status["warnings"]:
        log.info("Warnings:")
        for warning in status["warnings"]:
            log.info(f"  - {warning}")

    log.info("")
    log.info(f"{'IDX':>5} {'STATE':<8} {'OP':<10} {'CONN':>12} {'OP-ID':>12} {'DURATION':>12}")
    for worker in status["workers"]:
        op = worker["op"].upper() if worker["op"] else "-"
        log.info(
            f"{worker['idx']:>5} "
            f"{worker['state'].upper():<8} "
            f"{op:<10} "
            f"{_format_optional(worker['conn']):>12} "
            f"{_format_optional(worker['op_id']):>12} "
            f"{_format_duration_ns(worker['duration_ns']):>12}"
        )


def thread_pool_status(inst, log, args):
    status = _read_threadpool_status(inst)
    if args.json:
        log.info(json.dumps(status, indent=4))
    else:
        _emit_text(log, status)


def create_parser(subparsers):
    parser = subparsers.add_parser(
        "thread-pool-status",
        help="Display offline thread pool status from the local mmap diagnostics file",
        formatter_class=CustomHelpFormatter,
    )
    parser.set_defaults(func=thread_pool_status)
