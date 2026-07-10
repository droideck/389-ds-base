# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2015 Red Hat, Inc
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---
#
import pytest
from lib389.utils import *

#
# socket related functions
#
import socket
from contextlib import closing
from io import BytesIO


def test_socket_check_bind_available_port():
    """A port with no socket owner is available for a listener."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]

    assert socket_check_bind(port)


def test_socket_check_bind_detects_ipv4_listener():
    """An IPv4 socket is detected even when IPv6 is available."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(('0.0.0.0', 0))
        port = sock.getsockname()[1]

        assert not socket_check_bind(port)


def test_socket_check_bind_detects_client_source_port():
    """An established client's source port cannot become a listener."""
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


def test_socket_check_bind_allows_reusable_time_wait_port():
    """A server-side TIME_WAIT does not block an ns-slapd-style listener."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
        listener.listen(1)

        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as client:
            client.connect(listener.getsockname())
            connection, _ = listener.accept()
            connection.close()
            assert client.recv(1) == b''

    assert socket_check_bind(port)


def test_normalizeDN():
    test = [
        (r'dc=example,dc=com', r'dc=example,dc=com'),
        (r'dc=example, dc=com', r'dc=example,dc=com'),
        (r'cn="dc=example,dc=com",cn=config',
         'cn=dc\\=example\\,dc\\=com,cn=config'),
    ]
    for k, v in test:
        r = normalizeDN(k)
        assert r == v, "Mismatch %r vs %r" % (r, v)


def test_escapeDNValue():
    test = [(r'"dc=example, dc=com"', r'\"dc\=example\,\ dc\=com\"')]
    for k, v in test:
        r = escapeDNValue(k)
        assert r == v, "Mismatch %r vs %r" % (r, v)


def test_escapeDNFiltValue():
    test = [(r'"dc=example, dc=com"',
             '\\22dc\\3dexample\\2c\\20dc\\3dcom\\22')]
    for k, v in test:
        r = escapeDNFiltValue(k)
        assert r == v, "Mismatch %r vs %r" % (r, v)


def test_isLocalHost(monkeypatch):
    class FakeProcess:
        def __init__(self):
            self.stdout = BytesIO(b'inet 192.0.2.10/24')

        def wait(self):
            return 0

    def fake_gethostbyname(host):
        if host == 'unresolved.example.test':
            raise socket.gaierror
        return {
            'local-alias.example.test': '192.0.2.10',
            'remote.example.test': '198.51.100.10',
        }[host]

    monkeypatch.setattr('lib389.utils.socket.gethostname',
                        lambda: 'local.example.test')
    monkeypatch.setattr('lib389.utils.socket.gethostbyname',
                        fake_gethostbyname)
    monkeypatch.setattr('lib389.utils.subprocess.Popen',
                        lambda *args, **kwargs: FakeProcess())

    test = [
        ('localhost', True),
        ('localhost.localdomain', True),
        ('local.example.test', True),
        ('local-alias.example.test', True),
        ('remote.example.test', False),
        ('unresolved.example.test', False),
    ]
    for k, v in test:
        r = isLocalHost(k)
        assert r == v, "Mismatch %r vs %r on %r" % (r, v, k)


def test_update_newhost_with_fqdn(monkeypatch):
    fqdns = {
        '': 'local.example.test',
        'localhost': 'local.example.test',
        'remote': 'remote.example.test',
    }
    monkeypatch.setattr('lib389.utils.getfqdn', lambda host='': fqdns[host])
    monkeypatch.setattr('lib389.utils.isLocalHost',
                        lambda host: host == 'local.example.test')

    test = [
        ({'hostname': 'localhost'}, ('local.example.test', True)),
        ({'hostname': 'remote'}, ('remote.example.test', False)),
        ({}, ('local.example.test', True)),
    ]
    for k, v in test:
        old = k.copy()
        expected_host, expected_r = v
        r = update_newhost_with_fqdn(k)
        assert expected_r == r, "Mismatch %r vs %r for %r" % (
            r, expected_r, old)
        assert k['hostname'] == expected_host, "Mismatch %r vs %r for %r" % (
            k['hostname'], expected_host, old)


def test_formatInfData():
    ret = formatInfData({
        'hostname': 'localhost.localdomain',
        'user-id': 'dirsrv',
        'group-id': 'dirsrv',
        'ldap-port': 12345,
        'root-dn': 'cn=directory manager',
        'root-pw': 'password',
        'server-id': 'dirsrv',
        'suffix': 'o=base1',
        'strict_hostname_checking': True,
    })
    log.info("content: %r" % ret)


def test_formatInfData_withadmin():
    instance_params = {
        'hostname': 'localhost.localdomain',
        'user-id': 'dirsrv',
        'group-id': 'dirsrv',
        'ldap-port': 12346,
        'root-dn': 'cn=directory manager',
        'root-pw': 'password',
        'server-id': 'dirsrv',
        'suffix': 'o=base1',
        'strict_hostname_checking': True,
        }
    admin_params = {
        'have_admin': True,
        'create_admin': True,
        'admin_domain': 'example.com',
        'cfgdshost': 'localhost',
        'cfgdsport': 12346,
        'cfgdsuser': 'admin',
        'cfgdspwd': 'admin'}
    instance_params.update(admin_params)
    ret = formatInfData(instance_params)
    log.info("content: %r" % ret)


def test_formatInfData_withconfigserver():
    instance_params = {
        'hostname': 'localhost.localdomain',
        'user-id': 'dirsrv',
        'group-id': 'dirsrv',
        'ldap-port': 12346,
        'root-dn': 'cn=directory manager',
        'root-pw': 'password',
        'server-id': 'dirsrv',
        'suffix': 'o=base1',
        'strict_hostname_checking': True,
        }
    admin_params = {
        'have_admin': True,
        'cfgdshost': 'localhost',
        'cfgdsport': 12346,
        'cfgdsuser': 'admin',
        'cfgdspwd': 'admin',
        'admin_domain': 'example.com'}
    instance_params.update(admin_params)
    ret = formatInfData(instance_params)
    log.info("content: %r" % ret)


@pytest.mark.parametrize('data', [
    ({'userpaSSwoRd': '1234', 'nsslaPd-rootpw': '5678', 'regularAttr': 'originalvalue'},
     {'userpaSSwoRd': '********', 'nsslaPd-rootpw': '********', 'regularAttr': 'originalvalue'}),
    ({'userpassword': ['1', '2', '3'], 'nsslapd-rootpw': ['x']},
     {'userpassword': ['********', '********', '********'], 'nsslapd-rootpw': ['********']})
])
def test_get_log_data(data):
    before, after = data
    assert display_log_data(before) == after


@pytest.mark.parametrize('ds_ver, cmp_ver', [
    ('1.3.1', '1.3.2'),
    ('1.3.1', '1.3.10'),
    ('1.3.2', '1.3.10'),
    ('1.3.9', ('1.3.10', '1.4.2.0')),
    ('1.4.0.1', ('1.3.9', '1.4.1.0', '1.4.2.1')),
    ('1.4.1', '1.4.2.0-20191115gitbadc0ffee' ),
])
def test_ds_is_older_versions(monkeypatch, ds_ver, cmp_ver):
    monkeypatch.setattr('lib389.utils.get_ds_version',
                        lambda paths=None: ds_ver)
    comparison_versions = cmp_ver if isinstance(cmp_ver, tuple) else (cmp_ver,)
    assert ds_is_related('older', *comparison_versions)


@pytest.mark.parametrize('ds_ver, cmp_ver', [
    ('1.3.2', '1.3.1'),
    ('1.3.10', '1.3.1'),
    ('1.3.10', '1.3.2'),
    ('1.3.10', ('1.3.9', '1.4.2.0')),
    ('1.4.2.1', ('1.3.9', '1.4.0.1', '1.4.2.0')),
    ('1.4.2.0-20191115gitbadc0ffee', '1.4.1' ),
])
def test_ds_is_newer_versions(monkeypatch, ds_ver, cmp_ver):
    monkeypatch.setattr('lib389.utils.get_ds_version',
                        lambda paths=None: ds_ver)
    comparison_versions = cmp_ver if isinstance(cmp_ver, tuple) else (cmp_ver,)
    assert ds_is_related('newer', *comparison_versions)


@pytest.mark.parametrize('input, result', [
    (b'', ''),
    (b'\x00', '\\00'),
    (b'\x01\x00', '\\01\\00'),
    (b'01', '\\30\\31'),
    (b'101', '\\31\\30\\31'),
    (b'101x1', '\\31\\30\\31\\78\\31'),
    (b'0\x82\x05s0\x82\x03[\xa0\x03\x02\x01\x02', '\\30\\82\\05\\73\\30\\82\\03\\5b\\a0\\03\\02\\01\\02'),
])
def test_search_filter_escape_bytes(input, result):
    assert search_filter_escape_bytes(input) == result


if __name__ == "__main__":
    CURRENT_FILE = os.path.realpath(__file__)
    pytest.main("-s -v %s" % CURRENT_FILE)
