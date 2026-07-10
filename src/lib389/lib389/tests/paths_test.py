# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2016 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---
#

import pytest

from lib389.paths import MUST, Paths


@pytest.fixture
def defaults_inf(tmp_path, monkeypatch):
    values = {key: '/test/{}'.format(key) for key in MUST}
    values['version'] = '1.2.3'

    monkeypatch.delenv('PREFIX', raising=False)
    defaults_file = tmp_path / 'defaults.inf'
    defaults_file.write_text(
        '[slapd]\n{}\n'.format(
            '\n'.join('{} = {}'.format(key, value)
                      for key, value in values.items())),
        encoding='utf-8',
    )
    monkeypatch.setattr('lib389.paths.DEFAULTS_PATH', [str(defaults_file)])
    return values


# Test that we can retrieve the settings from the paths object
def test_paths(defaults_inf):
    # Make the paths object.
    p = Paths()
    # Get a value!
    assert p.version == defaults_inf['version']


# Test that if we make the path object, and we don't read a path from it
# the filecache state is False
def test_path_noread(defaults_inf):
    p = Paths()
    assert p._defaults_cached is False
    p._read_defaults()
    assert p._defaults_cached is True
    assert p._config.get('slapd', 'version') == defaults_inf['version']


def test_path_exception(monkeypatch):
    # Trigger the internal path find with a "bad location" and
    # make sure that we get the exception
    monkeypatch.delenv('PREFIX', raising=False)
    p = Paths()
    with pytest.raises(IOError):
        p._get_defaults_loc(search_paths=[])
