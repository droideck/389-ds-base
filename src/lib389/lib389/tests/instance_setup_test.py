# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2026 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---

import logging
import subprocess
from unittest.mock import Mock

import pytest

from lib389.instance import setup as setup_lib
from lib389.instance.setup import SetupDs


@pytest.fixture
def setup_ds(monkeypatch):
    installer = SetupDs(log=logging.getLogger(__name__))
    monkeypatch.setattr(installer, '_prepare_ds', Mock())
    monkeypatch.setattr(installer, '_prepare', Mock())
    monkeypatch.setattr(installer, '_install', Mock())
    monkeypatch.setattr(setup_lib, 'DEBUGGING', False)
    return installer


def test_create_from_args_cleans_up_systemd_start_failure(setup_ds, monkeypatch):
    """A systemd startup failure removes the partial installation."""
    error = subprocess.CalledProcessError(1, ['systemctl', 'start', 'dirsrv@test'])
    monkeypatch.setattr(setup_ds, '_install_ds', Mock(side_effect=error))
    cleanup = Mock()
    monkeypatch.setattr(setup_ds, '_remove_failed_install', cleanup)

    with pytest.raises(subprocess.CalledProcessError) as exc:
        setup_ds.create_from_args({}, {'instance_name': 'test'})

    assert exc.value is error
    cleanup.assert_called_once_with('test')


def test_create_from_args_cleanup_failure_does_not_mask_original(setup_ds, monkeypatch):
    """A failed cleanup preserves the original installation exception."""
    error = subprocess.CalledProcessError(1, ['systemctl', 'start', 'dirsrv@test'])
    monkeypatch.setattr(setup_ds, '_install_ds', Mock(side_effect=error))
    cleanup = Mock(side_effect=RuntimeError('cleanup failed'))
    monkeypatch.setattr(setup_ds, '_remove_failed_install', cleanup)

    with pytest.raises(subprocess.CalledProcessError) as exc:
        setup_ds.create_from_args({}, {'instance_name': 'test'})

    assert exc.value is error
    cleanup.assert_called_once_with('test')


def test_create_from_args_preserves_value_error_api(setup_ds, monkeypatch):
    """Installer ValueErrors retain the established wrapped API message."""
    error = ValueError('invalid setup')
    monkeypatch.setattr(setup_ds, '_install_ds', Mock(side_effect=error))
    cleanup = Mock()
    monkeypatch.setattr(setup_ds, '_remove_failed_install', cleanup)

    with pytest.raises(ValueError, match='Instance creation failed!  invalid setup') as exc:
        setup_ds.create_from_args({}, {'instance_name': 'test'})

    assert exc.value.__cause__ is error
    cleanup.assert_called_once_with('test')


def test_create_from_args_cleans_up_post_install_failure(setup_ds, monkeypatch):
    """A child post-install failure also removes the installed instance."""
    monkeypatch.setattr(setup_ds, '_install_ds', Mock())
    error = RuntimeError('post-install failed')
    setup_ds._install.side_effect = error
    cleanup = Mock()
    monkeypatch.setattr(setup_ds, '_remove_failed_install', cleanup)

    with pytest.raises(RuntimeError) as exc:
        setup_ds.create_from_args({}, {'instance_name': 'test'})

    assert exc.value is error
    cleanup.assert_called_once_with('test')


def test_create_from_args_preserves_post_install_value_error(setup_ds, monkeypatch):
    """A child post-install ValueError is propagated unchanged after cleanup."""
    class PostInstallError(ValueError):
        pass

    monkeypatch.setattr(setup_ds, '_install_ds', Mock())
    error = PostInstallError('post-install failed')
    setup_ds._install.side_effect = error
    cleanup = Mock()
    monkeypatch.setattr(setup_ds, '_remove_failed_install', cleanup)

    with pytest.raises(PostInstallError) as exc:
        setup_ds.create_from_args({}, {'instance_name': 'test'})

    assert exc.value is error
    assert str(exc.value) == 'post-install failed'
    cleanup.assert_called_once_with('test')


def test_create_from_args_preserves_failed_install_when_debugging(setup_ds, monkeypatch):
    """DEBUGGING keeps the partial instance available for investigation."""
    monkeypatch.setattr(setup_lib, 'DEBUGGING', '1')
    error = subprocess.CalledProcessError(1, ['systemctl', 'start', 'dirsrv@test'])
    monkeypatch.setattr(setup_ds, '_install_ds', Mock(side_effect=error))
    cleanup = Mock()
    monkeypatch.setattr(setup_ds, '_remove_failed_install', cleanup)

    with pytest.raises(subprocess.CalledProcessError) as exc:
        setup_ds.create_from_args({}, {'instance_name': 'test'})

    assert exc.value is error
    cleanup.assert_not_called()
