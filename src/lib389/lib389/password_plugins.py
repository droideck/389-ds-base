# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2018 William Brown <william@blackhats.net.au>
# Copyright (C) 2023 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---

from lib389.plugins import Plugin, Plugins
from lib389._constants import DN_PWDSTORAGE_SCHEMES


class PasswordPlugin(Plugin):
    _plugin_properties = {
        'nsslapd-pluginpath': 'libpwdstorage-plugin',
        'nsslapd-plugintype': 'pwdstoragescheme',
        'nsslapd-pluginEnabled' : 'on'
    }

    def __init__(self, instance, dn=None):
        super(PasswordPlugin, self).__init__(instance, dn)
        self._rdn_attribute = 'cn'
        self._must_attributes = [
            'nsslapd-pluginEnabled',
            'nsslapd-pluginPath',
            'nsslapd-pluginInitfunc',
            'nsslapd-pluginType',
            ]
        self._create_objectclasses = ['top', 'nsslapdplugin']
        # We'll mark this protected, and people can just disable the plugins.
        self._protected = True


class SSHA512Plugin(PasswordPlugin):
    def __init__(self, instance, dn=f'cn=SSHA512,{DN_PWDSTORAGE_SCHEMES}'):
        super(SSHA512Plugin, self).__init__(instance, dn)


class SHAPlugin(PasswordPlugin):
    def __init__(self, instance, dn=f'cn=SHA,{DN_PWDSTORAGE_SCHEMES}'):
        super(SHAPlugin, self).__init__(instance, dn)


class CRYPTPlugin(PasswordPlugin):
    def __init__(self, instance, dn=f'cn=CRYPT,{DN_PWDSTORAGE_SCHEMES}'):
        super(CRYPTPlugin, self).__init__(instance, dn)


class SSHAPlugin(PasswordPlugin):
    def __init__(self, instance, dn=f'cn=SSHA,{DN_PWDSTORAGE_SCHEMES}'):
        super(SSHAPlugin, self).__init__(instance, dn)


class PBKDF2BasePlugin(PasswordPlugin):
    """Base class for all PBKDF2 variants"""
    def __init__(self, instance, dn):
        super(PBKDF2BasePlugin, self).__init__(instance, dn)
        self._create_objectclasses.append('pwdPBKDF2PluginConfig')
        
    def set_rounds(self, rounds):
        """Set the number of rounds for PBKDF2 hashing (requires restart)
        
        :param rounds: Number of rounds (10000-1000000)
        :type rounds: int
        """
        rounds = int(rounds)
        if rounds < 10000 or rounds > 1000000:
            raise ValueError("PBKDF2 rounds must be between 10000 and 1000000")
        self.replace('nsslapd-pwdPBKDF2Rounds', str(rounds))
        
    def get_rounds(self):
        """Get the current number of rounds
        
        :returns: Current rounds setting or 10000 if not set
        :rtype: int
        """
        rounds = self.get_attr_val_utf8('nsslapd-pwdPBKDF2Rounds')
        return int(rounds) if rounds else 10000


class PBKDF2SHA1Plugin(PBKDF2BasePlugin):
    """PBKDF2-SHA1 password storage scheme"""
    def __init__(self, instance, dn=f'cn=PBKDF2-SHA1,{DN_PWDSTORAGE_SCHEMES}'):
        super(PBKDF2SHA1Plugin, self).__init__(instance, dn)
        self._plugin_properties.update({
            'nsslapd-pluginInitfunc': 'pwdchan_pbkdf2_sha1_init'
        })


class PBKDF2SHA256Plugin(PBKDF2BasePlugin):
    """PBKDF2-SHA256 password storage scheme"""
    def __init__(self, instance, dn=f'cn=PBKDF2-SHA256,{DN_PWDSTORAGE_SCHEMES}'):
        super(PBKDF2SHA256Plugin, self).__init__(instance, dn)
        self._plugin_properties.update({
            'nsslapd-pluginInitfunc': 'pwdchan_pbkdf2_sha256_init'
        })


class PBKDF2SHA512Plugin(PBKDF2BasePlugin):
    """PBKDF2-SHA512 password storage scheme"""
    def __init__(self, instance, dn=f'cn=PBKDF2-SHA512,{DN_PWDSTORAGE_SCHEMES}'):
        super(PBKDF2SHA512Plugin, self).__init__(instance, dn)
        self._plugin_properties.update({
            'nsslapd-pluginInitfunc': 'pwdchan_pbkdf2_sha512_init'
        })


class PasswordPlugins(Plugins):
    def __init__(self, instance):
        super(PasswordPlugins, self).__init__(instance=instance)
        self._objectclasses = ['nsSlapdPlugin']
        self._filterattrs = ['cn']
        self._childobject = PasswordPlugin
        self._basedn = DN_PWDSTORAGE_SCHEMES
