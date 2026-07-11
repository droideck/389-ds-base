# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2026 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---
#
import logging
import socket
import subprocess
from contextlib import closing
from unittest.mock import MagicMock, Mock, patch

import pytest

from lib389 import DirSrv
from lib389.instance import setup as setup_lib
from lib389.instance.setup import SetupDs
from lib389.utils import socket_check_bind


pytestmark = pytest.mark.tier0


def _error_messages(log):
    messages = []
    for call in log.error.call_args_list:
        if not call.args:
            continue
        if len(call.args) == 1:
            messages.append(str(call.args[0]))
        else:
            messages.append(str(call.args[0]) % tuple(call.args[1:]))
    return '\n'.join(messages)


def test_socket_check_bind_matches_server_listener_semantics():
    """The bind check distinguishes a client source port from server TIME_WAIT

    :id: d112ee4f-f3d0-4a21-9a6b-f421e38e7d82
    :setup: Local IPv4 TCP listeners and clients
    :steps:
        1. Bind the client to a kernel-selected local source port
        2. Connect the client and accept the connection
        3. Check whether the client source port can be bound as a listener
        4. Actively close a reusable server connection and check its listener port
    :expectedresults:
        1. The client owns a concrete local source port
        2. The connection is established
        3. The wildcard bind check reports that the source port is unavailable
        4. A server-side TIME_WAIT does not block an ns-slapd-style listener
    """
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)

        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as client:
            client.bind(('127.0.0.1', 0))
            source_port = client.getsockname()[1]
            client.connect(listener.getsockname())

            connection, _ = listener.accept()
            with closing(connection):
                assert not socket_check_bind(source_port)

    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', 0))
        server_port = listener.getsockname()[1]
        listener.listen(1)

        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as client:
            client.connect(listener.getsockname())
            connection, _ = listener.accept()
            connection.close()
            assert client.recv(1) == b''

    assert socket_check_bind(server_port)


@pytest.mark.parametrize('cleanup_fails', [False, True],
                         ids=['cleanup-succeeds', 'cleanup-fails'])
def test_setup_rolls_back_systemd_start_failure(monkeypatch, cleanup_fails):
    """Setup rollback never masks a systemd instance-start failure

    :id: cdbf0c4b-9545-4966-8255-9279d7499022
    :setup: A mocked instance installer in non-debug mode
    :steps:
        1. Make systemd instance startup raise CalledProcessError
        2. Run setup with successful or failing partial-install cleanup
        3. Inspect the cleanup call and propagated exception
    :expectedresults:
        1. Setup enters its failed-install rollback path
        2. Rollback is attempted in both cases
        3. The original CalledProcessError object is propagated unchanged
    :parametrized: yes
    """
    installer = SetupDs(log=logging.getLogger(__name__))
    monkeypatch.setattr(installer, '_prepare_ds', Mock())
    monkeypatch.setattr(installer, '_prepare', Mock())
    monkeypatch.setattr(installer, '_install', Mock())
    monkeypatch.setattr(setup_lib, 'DEBUGGING', False)

    start_error = subprocess.CalledProcessError(
        1, ['systemctl', 'start', 'dirsrv@test']
    )
    monkeypatch.setattr(installer, '_install_ds', Mock(side_effect=start_error))
    cleanup_error = RuntimeError('cleanup failed') if cleanup_fails else None
    cleanup = Mock(side_effect=cleanup_error)
    monkeypatch.setattr(installer, '_remove_failed_install', cleanup)

    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        installer.create_from_args({}, {'instance_name': 'test'})

    assert exc_info.value is start_error
    cleanup.assert_called_once_with('test')


def test_setup_preserves_install_hook_value_error(monkeypatch):
    """Setup preserves a custom ValueError from the documented install hook

    :id: 11a1c1cb-8dbf-4501-8020-4cd5c0b716f0
    :setup: A mocked instance installer in non-debug mode
    :steps:
        1. Complete the core instance installation successfully
        2. Make the child _install hook raise a custom ValueError subclass
        3. Run setup and inspect cleanup and the propagated exception
    :expectedresults:
        1. The core installation completes before the child hook runs
        2. The hook failure enters the failed-install cleanup path
        3. Cleanup is attempted and the original exception object, subtype, and message are preserved
    """
    class InstallHookError(ValueError):
        """A documented child install-hook failure."""

    installer = SetupDs(log=logging.getLogger(__name__))
    monkeypatch.setattr(installer, '_prepare_ds', Mock())
    monkeypatch.setattr(installer, '_prepare', Mock())
    monkeypatch.setattr(setup_lib, 'DEBUGGING', False)

    call_order = []
    install_ds = Mock(side_effect=lambda *args: call_order.append('_install_ds'))
    hook_error = InstallHookError('documented install hook failed')

    def fail_install_hook(extra):
        call_order.append('_install')
        raise hook_error

    install_hook = Mock(side_effect=fail_install_hook)
    cleanup = Mock()
    monkeypatch.setattr(installer, '_install_ds', install_ds)
    monkeypatch.setattr(installer, '_install', install_hook)
    monkeypatch.setattr(installer, '_remove_failed_install', cleanup)

    with pytest.raises(InstallHookError) as exc_info:
        installer.create_from_args({}, {'instance_name': 'test'})

    assert call_order == ['_install_ds', '_install']
    assert exc_info.value is hook_error
    assert type(exc_info.value) is InstallHookError
    assert str(exc_info.value) == 'documented install hook failed'
    cleanup.assert_called_once_with('test')


def test_start_failure_diagnostics_are_actionable_and_non_masking():
    """Startup diagnostics report a colliding client without masking the failure

    :id: 6af9778f-6e4e-4ffb-87c3-71125acc11b8
    :setup: A mocked local instance with systemd and TCP socket output
    :steps:
        1. Provide one unrelated socket and one client using the LDAP port as its source port
        2. Make an instance-state diagnostic and the error-log dump fail
        3. Make systemd startup fail and inspect the exception and diagnostic log
    :expectedresults:
        1. The socket diagnostics retain the matching client and process only
        2. Diagnostic sub-step and error-log failures do not interrupt handling
        3. The original exception is unchanged and no unrelated or secret values are logged
    """
    log = MagicMock()
    instance = DirSrv(external_log=log)
    instance.isLocal = True
    instance.serverid = 'standalone2'
    instance.port = 38902
    instance.sslport = 63602
    instance.bindpw = 'super-secret-password'
    instance.status = MagicMock(return_value=False)
    instance.with_systemd_running = MagicMock(return_value=True)
    instance.exists = MagicMock(side_effect=RuntimeError('diagnostic-secret'))
    instance._read_start_failure_port_setting = MagicMock(
        side_effect=OSError('procfs-secret')
    )
    instance.dump_errorlog = MagicMock(side_effect=RuntimeError('error-log-secret'))

    socket_output = (
        'State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n'
        'ESTAB 0 0 192.0.2.10:53000 198.51.100.10:443 '
        'users:(("unrelated-process",pid=10,fd=3))\n'
        'ESTAB 0 0 192.0.2.10:38902 192.0.2.20:38901 '
        'users:(("python3",pid=20,fd=4))\n'
    )
    socket_result = subprocess.CompletedProcess(['ss', '-tanp'], 0, socket_output)
    start_error = subprocess.CalledProcessError(
        1, ['systemctl', 'start', 'dirsrv@standalone2'], output=None
    )

    with patch('lib389.subprocess.run', return_value=socket_result), \
            patch('lib389.subprocess.check_output', side_effect=start_error):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            instance.start(post_open=False)

    assert exc_info.value is start_error
    messages = _error_messages(log)
    assert "exists='unavailable (RuntimeError)'" in messages
    assert '192.0.2.10:38902' in messages
    assert 'python3' in messages
    assert 'unrelated-process' not in messages
    assert instance.bindpw not in messages
    assert 'diagnostic-secret' not in messages
    assert 'procfs-secret' not in messages
    assert 'error-log-secret' not in messages
