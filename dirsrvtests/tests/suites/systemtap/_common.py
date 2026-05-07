# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2026 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---
"""Shared helpers for the systemtap test suite."""
import glob
import os
import subprocess


def ns_slapd_path(topo):
    return os.path.join(topo.standalone.ds_paths.sbin_dir, "ns-slapd")


def libslapd_path(topo):
    candidates = []
    for stem in ("libslapd.so", "libslapd.so.*"):
        candidates.extend(
            glob.glob(os.path.join(topo.standalone.ds_paths.lib_dir, "dirsrv", stem))
        )
        candidates.extend(
            glob.glob(os.path.join(topo.standalone.ds_paths.lib_dir, stem))
        )
    concrete = [p for p in candidates if not os.path.islink(p)]
    return (concrete or candidates or [None])[0]


def binary_has_sdt_notes(binary):
    out = subprocess.run(
        ["readelf", "-n", binary],
        capture_output=True, text=True, check=True,
    ).stdout
    return "stapsdt" in out
