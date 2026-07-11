# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2026 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---

import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from lib389 import DirSrv


def _instance():
    log = MagicMock()
    instance = DirSrv(external_log=log)
    instance.isLocal = True
    instance.serverid = 'standalone2'
    instance.port = 38902
    instance.sslport = 63602
    instance.bindpw = 'super-secret-password'
    instance.exists = MagicMock(return_value=True)
    return instance, log


def _error_messages(log):
    messages = []
    for call in log.error.call_args_list:
        args = call.args
        if not args:
            continue
        if len(args) == 1:
            messages.append(str(args[0]))
        else:
            messages.append(str(args[0]) % tuple(args[1:]))
    return '\n'.join(messages)


def test_start_failure_diagnostics_logs_client_source_socket():
    """The socket report includes source-port collisions and excludes unrelated rows."""
    instance, log = _instance()
    ss_output = """State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
ESTAB 0 0 192.0.2.10:53000 198.51.100.10:443 users:((\"unrelated-process\",pid=10,fd=3))
ESTAB 0 0 192.0.2.10:38902 192.0.2.20:38901 users:((\"python3\",pid=20,fd=4))
LISTEN 0 128 *:63602 *:* users:((\"ns-slapd\",pid=30,fd=5))
"""
    completed = subprocess.CompletedProcess(['ss', '-tanp'], 0, ss_output)
    settings = {
        '/proc/sys/net/ipv4/ip_local_port_range': '32768 60999',
        '/proc/sys/net/ipv4/ip_local_reserved_ports': '38901-39299',
    }

    with patch('lib389.subprocess.run', return_value=completed) as run:
        instance._read_start_failure_port_setting = MagicMock(
            side_effect=lambda path: settings[path]
        )
        instance._log_start_failure_diagnostics()

    run.assert_called_once_with(
        ['ss', '-tanp'],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        timeout=5,
        check=False,
        shell=False
    )
    messages = _error_messages(log)
    assert "serverid='standalone2'" in messages
    assert 'exists=True' in messages
    assert 'LDAP port=38902' in messages
    assert 'LDAPS port=63602' in messages
    assert "ip_local_port_range='32768 60999'" in messages
    assert "ip_local_reserved_ports='38901-39299'" in messages
    assert '192.0.2.10:38902' in messages
    assert 'python3' in messages
    assert '*:63602' in messages
    assert 'ns-slapd' in messages
    assert 'unrelated-process' not in messages
    assert instance.bindpw not in messages


def test_start_failure_socket_diagnostics_falls_back_to_lsof():
    """lsof supplies ownership and state if ss is unavailable."""
    instance, _ = _instance()

    def command_result(command):
        if command[0] == 'ss':
            raise FileNotFoundError('ss')
        if command[0] == 'lsof':
            return subprocess.CompletedProcess(
                command, 0,
                'COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n'
                'python3 42 root 7u IPv4 1 0t0 TCP 192.0.2.10:38902->192.0.2.20:38901 (ESTABLISHED)\n'
            )
        raise AssertionError('Unexpected command: %r' % command)

    instance._run_start_failure_diagnostic_command = MagicMock(side_effect=command_result)
    source, rows = instance._collect_start_failure_socket_diagnostics([38902, 63602])

    assert source == 'lsof -nP -iTCP:<port>'
    assert any('python3' in row and '(ESTABLISHED)' in row for row in rows)
    assert [entry.args[0] for entry in
            instance._run_start_failure_diagnostic_command.call_args_list] == [
        ['ss', '-tanp'],
        ['lsof', '-nP', '-iTCP:38902', '-iTCP:63602'],
    ]


def test_systemd_start_diagnostics_do_not_mask_original_exception():
    """Diagnostic and error-log failures cannot replace systemctl's exception."""
    instance, log = _instance()
    instance.status = MagicMock(return_value=False)
    instance.with_systemd_running = MagicMock(return_value=True)
    instance.exists = MagicMock(side_effect=RuntimeError('diagnostic-secret'))
    instance._read_start_failure_port_setting = MagicMock(side_effect=OSError('no procfs'))
    instance._collect_start_failure_socket_diagnostics = MagicMock(
        side_effect=RuntimeError('diagnostic-secret')
    )
    instance.dump_errorlog = MagicMock(side_effect=RuntimeError('error-log-secret'))
    start_error = subprocess.CalledProcessError(
        1, ['systemctl', 'start', 'dirsrv@standalone2'], output=None
    )

    with patch('lib389.subprocess.check_output', side_effect=start_error):
        with pytest.raises(subprocess.CalledProcessError) as exc:
            instance.start(post_open=False)

    assert exc.value is start_error
    messages = _error_messages(log)
    assert 'exists=\'unavailable (RuntimeError)\'' in messages
    assert 'TCP socket diagnostics failed (RuntimeError)' in messages
    assert 'diagnostic-secret' not in messages
    assert 'error-log-secret' not in messages
    assert instance.bindpw not in messages


def test_direct_start_diagnostics_preserve_start_error_as_cause():
    """Direct ns-slapd failures retain their CalledProcessError as the cause."""
    instance, log = _instance()
    instance.status = MagicMock(return_value=False)
    instance.with_systemd_running = MagicMock(return_value=False)
    instance.has_asan = MagicMock(return_value=False)
    instance.get_sbin_dir = MagicMock(return_value='/usr/sbin')
    instance.pid_file = MagicMock(return_value='/run/dirsrv/slapd-standalone2.pid')
    instance.ds_paths = SimpleNamespace(
        config_dir='/etc/dirsrv/slapd-standalone2',
        run_dir='/run/dirsrv'
    )
    instance._read_start_failure_port_setting = MagicMock(side_effect=OSError('no procfs'))
    instance._collect_start_failure_socket_diagnostics = MagicMock(return_value=('ss -tanp', []))
    instance.dump_errorlog = MagicMock(side_effect=RuntimeError('error-log-secret'))
    start_error = subprocess.CalledProcessError(
        1, ['/usr/sbin/ns-slapd'], output=b'\xff bind failed'
    )

    with patch('lib389.subprocess.check_output', side_effect=start_error):
        with pytest.raises(ValueError, match='Failed to start DS') as exc:
            instance.start(post_open=False)

    assert exc.value.__cause__ is start_error
    messages = _error_messages(log)
    assert '\ufffd bind failed' in messages
    assert 'error-log-secret' not in messages
    assert instance.bindpw not in messages
