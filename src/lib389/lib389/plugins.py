# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2015 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---

import ldap
import copy
import os.path

from lib389 import tasks
from lib389._mapped_object import DSLdapObjects, DSLdapObject
from lib389.lint import DSRILE0001
from lib389._constants import DN_PLUGIN
from lib389.properties import (
        PLUGINS_OBJECTCLASS_VALUE, PLUGIN_PROPNAME_TO_ATTRNAME,
        PLUGINS_ENABLE_ON_VALUE, PLUGINS_ENABLE_OFF_VALUE, PLUGIN_ENABLE
        )


class Plugin(DSLdapObject):
    """A single instance of a plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    _plugin_properties = {
        'nsslapd-pluginEnabled' : 'off'
    }

    def __init__(self, instance, dn=None):
        super(Plugin, self).__init__(instance, dn)
        self._rdn_attribute = 'cn'
        self._must_attributes = [
            'nsslapd-pluginEnabled',
            'nsslapd-pluginPath',
            'nsslapd-pluginInitfunc',
            'nsslapd-pluginType',
            'nsslapd-pluginId',
            'nsslapd-pluginVendor',
            'nsslapd-pluginVersion',
            'nsslapd-pluginDescription',
            ]
        self._create_objectclasses = ['top', 'nsslapdplugin']
        # We'll mark this protected, and people can just disable the plugins.
        self._protected = True

    def enable(self):
        """Set nsslapd-pluginEnabled to on"""

        self.set('nsslapd-pluginEnabled', 'on')

    def disable(self):
        """Set nsslapd-pluginEnabled to off"""

        self.set('nsslapd-pluginEnabled', 'off')

    def restart(self):
        """Disable and then enable the plugin"""

        self.disable()
        self.enable()

    def status(self):
        """Check if the plugin is enabled"""

        return self.get_attr_val_utf8('nsslapd-pluginEnabled') == 'on'

    def create(self, rdn=None, properties=None, basedn=None):
        """Create a plugin entry

        When we create plugins, we don't want people to have to consider all
        the little details. Plus, the server during creation needs to be able
        to create these from nothing.
        As a result, all the named plugins carry a default properties
        dictionary that can be used.

        :param rdn: RDN of the new entry
        :type rdn: str
        :param properties: Attributes for the new entry
        :type properties: dict
        :param basedn: Base DN of the new entry
        :type rdn: str

        :returns: Plugin class instance of the created entry
        """

        # Copy the plugin internal properties.
        internal_properties = copy.deepcopy(self._plugin_properties)
        if properties is not None:
            internal_properties.update(properties)
        return super(Plugin, self).create(rdn, internal_properties, basedn)


class AddnPlugin(Plugin):
    """An instance of addn plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn="cn=addn,cn=plugins,cn=config"):
        super(AddnPlugin, self).__init__(instance, dn)
        # Need to add wrappers to add domains to this.


class AttributeUniquenessPlugin(Plugin):
    """An instance of attribute uniqueness plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn="cn=attribute uniqueness,cn=plugins,cn=config"):
        super(AttributeUniquenessPlugin, self).__init__(instance, dn)

    ## These are some wrappers to the important attributes
    # This plugin will be "tricky" in that it can have "many" instance
    # of the plugin, rather than many configs.

    def add_unique_attribute(self, attr):
        """Add a uniqueness-attribute-name attribute"""

        self.add('uniqueness-attribute-name', attr)

    def remove_unique_attribute(self, attr):
        """Remove a uniqueness-attribute-name attribute"""

        self.remove('uniqueness-attribute-name', attr)

    def add_unique_subtree(self, basedn):
        """Add a uniqueness-subtree attribute"""

        self.add('uniqueness-subtrees', basedn)

    def remove_unique_subtree(self, basedn):
        """Remove a uniqueness-subtree attribute"""

        self.remove('uniqueness-subtrees', basedn)

    def enable_all_subtrees(self):
        """Set uniqueness-across-all-subtrees to on"""

        self.set('uniqueness-across-all-subtrees', 'on')

    def disable_all_subtrees(self):
        """Set uniqueness-across-all-subtrees to off"""

        self.set('uniqueness-across-all-subtrees', 'off')


class LdapSSOTokenPlugin(Plugin):
    """An instance of ldapssotoken plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    _plugin_properties = {
        'cn' : 'ldapssotoken',
        'nsslapd-pluginEnabled' : 'off',
        'nsslapd-pluginPath' : 'liblst-plugin',
        'nsslapd-pluginInitfunc' : 'lst_init',
        'nsslapd-pluginType' : 'extendedop',
        'nsslapd-pluginId' : 'ldapssotoken-plugin',
        'nsslapd-pluginVendor' : '389 Project',
        'nsslapd-pluginVersion' : '1.3.6',
        'nsslapd-pluginDescription' : 'Ldap SSO Token Sasl Mech - draft-wibrown-ldapssotoken',
    }

    def __init__(self, instance, dn="cn=ldapssotoken,cn=plugins,cn=config"):
        super(LdapSSOTokenPlugin, self).__init__(instance, dn)


class ManagedEntriesPlugin(Plugin):
    """An instance of managed entries plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn="cn=managed entries,cn=plugins,cn=config"):
        super(ManagedEntriesPlugin, self).__init__(instance, dn)


class MEPConfig(DSLdapObject):
    """A single instance of MEP config entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn):
        super(MEPConfig, self).__init__(instance, dn)
        self._rdn_attribute = 'cn'
        self._must_attributes = ['cn']
        self._create_objectclasses = ['top', 'extensibleObject']
        self._protected = False


class MEPConfigs(DSLdapObjects):
    """A DSLdapObjects entity which represents MEP config entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param basedn: Base DN for all account entries below
    :type basedn: str
    """

    def __init__(self, instance, basedn="cn=managed entries,cn=plugins,cn=config"):
        super(MEPConfigs, self).__init__(instance)
        self._objectclasses = ['top', 'extensibleObject']
        self._filterattrs = ['cn']
        self._childobject = MEPConfig
        self._basedn = basedn


class MEPTemplate(DSLdapObject):
    """A single instance of MEP template entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn=None):
        super(MEPTemplate, self).__init__(instance, dn)
        self._rdn_attribute = 'cn'
        self._must_attributes = ['cn']
        self._create_objectclasses = ['top', 'extensibleObject', 'mepTemplateEntry']
        self._protected = False


class MEPTemplates(DSLdapObjects):
    """A DSLdapObjects entity which represents MEP template entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param basedn: Base DN for all account entries below
    :type basedn: str
    """

    def __init__(self, instance, basedn):
        super(MEPTemplates, self).__init__(instance)
        self._objectclasses = ['top', 'extensibleObject']
        self._filterattrs = ['cn']
        self._childobject = MEPTemplate
        self._basedn = basedn


class ReferentialIntegrityPlugin(Plugin):
    """An instance of referential integrity postoperation plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    _plugin_properties = {
        'cn' : 'referential integrity postoperation',
        'nsslapd-pluginEnabled': 'off',
        'nsslapd-pluginPath': 'libreferint-plugin',
        'nsslapd-pluginInitfunc': 'referint_postop_init',
        'nsslapd-pluginType': 'betxnpostoperation',
        'nsslapd-pluginprecedence': '40',
        'nsslapd-plugin-depends-on-type': 'database',
        'referint-update-delay': '0',
        'referint-membership-attr': ['member', 'uniquemember', 'owner', 'seeAlso',],
        'nsslapd-pluginId' : 'referint',
        'nsslapd-pluginVendor' : '389 Project',
        'nsslapd-pluginVersion' : '1.3.7.0',
        'nsslapd-pluginDescription' : 'referential integrity plugin',
    }

    def __init__(self, instance, dn="cn=referential integrity postoperation,cn=plugins,cn=config"):
        super(ReferentialIntegrityPlugin, self).__init__(instance, dn)
        self._create_objectclasses.extend(['extensibleObject'])
        self._must_attributes.extend([
            'referint-update-delay',
            'referint-logfile',
            'referint-membership-attr',
        ])
        self._lint_functions = [self._lint_update_delay]

    def create(self, rdn=None, properties=None, basedn=None):
        """Create an instance of the plugin"""

        referint_log = os.path.join(self._instance.ds_paths.log_dir, "referint")
        if properties is None:
            properties = {'referint-logfile': referint_log}
        else:
            properties['referint-logfile'] = referint_log
        return super(ReferentialIntegrityPlugin, self).create(rdn, properties, basedn)

    def _lint_update_delay(self):
        if self.status():
            delay = self.get_attr_val_int("referint-update-delay")
            if delay is not None and delay != 0:
                return DSRILE0001

    def get_update_delay(self):
        """Get referint-update-delay attribute"""

        return self.get_attr_val_int('referint-update-delay')

    def get_update_delay_formatted(self):
        """Display referint-update-delay attribute"""

        return self.display_attr('referint-update-delay')

    def set_update_delay(self, value):
        """Set referint-update-delay attribute"""

        self.set('referint-update-delay', str(value))

    def get_membership_attr(self, formatted=False):
        """Get referint-membership-attr attribute"""

        return self.get_attr_vals_utf8('referint-membership-attr')

    def get_membership_attr_formatted(self):
        """Display referint-membership-attr attribute"""

        return self.display_attr('referint-membership-attr')

    def add_membership_attr(self, attr):
        """Add referint-membership-attr attribute"""

        self.add('referint-membership-attr', attr)

    def remove_membership_attr(self, attr):
        """Remove referint-membership-attr attribute"""

        self.remove('referint-membership-attr', attr)

    def get_entryscope(self, formatted=False):
        """Get nsslapd-pluginentryscope attribute"""

        return self.get_attr_vals_utf8('nsslapd-pluginentryscope')

    def get_entryscope_formatted(self):
        """Display nsslapd-pluginentryscope attribute"""

        return self.display_attr('nsslapd-pluginentryscope')

    def add_entryscope(self, attr):
        """Add nsslapd-pluginentryscope attribute"""

        self.add('nsslapd-pluginentryscope', attr)

    def remove_entryscope(self, attr):
        """Remove nsslapd-pluginentryscope attribute"""

        self.remove('nsslapd-pluginentryscope', attr)

    def remove_all_entryscope(self):
        """Remove all nsslapd-pluginentryscope attributes"""

        self.remove_all('nsslapd-pluginentryscope')

    def get_excludescope(self):
        """Get nsslapd-pluginexcludeentryscope attribute"""

        return self.get_attr_vals_ut8('nsslapd-pluginexcludeentryscope')

    def get_excludescope_formatted(self):
        """Display nsslapd-pluginexcludeentryscope attribute"""

        return self.display_attr('nsslapd-pluginexcludeentryscope')

    def add_excludescope(self, attr):
        """Add nsslapd-pluginexcludeentryscope attribute"""

        self.add('nsslapd-pluginexcludeentryscope', attr)

    def remove_excludescope(self, attr):
        """Remove nsslapd-pluginexcludeentryscope attribute"""

        self.remove('nsslapd-pluginexcludeentryscope', attr)

    def remove_all_excludescope(self):
        """Remove all nsslapd-pluginexcludeentryscope attributes"""

        self.remove_all('nsslapd-pluginexcludeentryscope')

    def get_container_scope(self):
        """Get nsslapd-plugincontainerscope attribute"""

        return self.get_attr_vals_ut8('nsslapd-plugincontainerscope')

    def get_container_scope_formatted(self):
        """Display nsslapd-plugincontainerscope attribute"""

        return self.display_attr('nsslapd-plugincontainerscope')

    def add_container_scope(self, attr):
        """Add nsslapd-plugincontainerscope attribute"""

        self.add('nsslapd-plugincontainerscope', attr)

    def remove_container_scope(self, attr):
        """Remove nsslapd-plugincontainerscope attribute"""

        self.remove('nsslapd-plugincontainerscope', attr)

    def remove_all_container_scope(self):
        """Remove all nsslapd-plugincontainerscope attributes"""

        self.remove_all('nsslapd-plugincontainerscope')

    def get_configarea(self):
        """Get nsslapd-pluginConfigArea attribute"""

        return self.get_attr_val_utf8_l('nsslapd-pluginConfigArea')

    def set_configarea(self, attr):
        """Set nsslapd-pluginConfigArea attribute"""

        return self.set('nsslapd-pluginConfigArea', attr)

    def remove_configarea(self):
        """Remove all nsslapd-pluginConfigArea attributes"""

        return self.remove_all('nsslapd-pluginConfigArea')


class ReferentialIntegrityConfig(DSLdapObject):
    """An instance of Referential Integrity config entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn):
        super(ReferentialIntegrityConfig, self).__init__(instance, dn)
        self._dn = dn
        self._rdn_attribute = 'cn'
        self._must_attributes = ['cn',
                                 'referint-update-delay',
                                 'referint-logfile',
                                 'referint-membership-attr']
        self._create_objectclasses = ['top', 'extensibleObject']
        self._protected = False
        self._exit_code = None


class SyntaxValidationPlugin(Plugin):
    """An instance of Syntax Validation Task plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn="cn=Syntax Validation Task,cn=plugins,cn=config"):
        super(SyntaxValidationPlugin, self).__init__(instance, dn)


class SchemaReloadPlugin(Plugin):
    """An instance of Schema Reload plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn="cn=Schema Reload,cn=plugins,cn=config"):
        super(SchemaReloadPlugin, self).__init__(instance, dn)


class StateChangePlugin(Plugin):
    """An instance of State Change plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn="cn=State Change Plugin,cn=plugins,cn=config"):
        super(StateChangePlugin, self).__init__(instance, dn)


class ACLPlugin(Plugin):
    """An instance of addn plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn="cn=ACL Plugin,cn=plugins,cn=config"):
        super(ACLPlugin, self).__init__(instance, dn)


class ACLPreoperationPlugin(Plugin):
    """An instance of ACL preoperation plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn="cn=ACL preoperation,cn=plugins,cn=config"):
        super(ACLPreoperationPlugin, self).__init__(instance, dn)


class RolesPlugin(Plugin):
    """An instance of Roles plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn="cn=Roles Plugin,cn=plugins,cn=config"):
        super(RolesPlugin, self).__init__(instance, dn)


class MemberOfPlugin(Plugin):
    """An instance of MemberOf plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    _plugin_properties = {
        'cn' : 'MemberOf Plugin',
        'nsslapd-pluginEnabled' : 'off',
        'nsslapd-pluginPath' : 'libmemberof-plugin',
        'nsslapd-pluginInitfunc' : 'memberof_postop_init',
        'nsslapd-pluginType' : 'betxnpostoperation',
        'nsslapd-plugin-depends-on-type' : 'database',
        'nsslapd-pluginId' : 'memberof',
        'nsslapd-pluginVendor' : '389 Project',
        'nsslapd-pluginVersion' : '1.3.7.0',
        'nsslapd-pluginDescription' : 'memberof plugin',
        'memberOfGroupAttr' : 'member',
        'memberOfAttr' : 'memberOf',
    }

    def __init__(self, instance, dn="cn=MemberOf Plugin,cn=plugins,cn=config"):
        super(MemberOfPlugin, self).__init__(instance, dn)
        self._create_objectclasses.extend(['extensibleObject'])
        self._must_attributes.extend(['memberOfGroupAttr', 'memberOfAttr'])

    def get_attr(self):
        """Get memberofattr attribute"""

        return self.get_attr_val_utf8_l('memberofattr')

    def get_attr_formatted(self):
        """Display memberofattr attribute"""

        return self.display_attr('memberofattr')

    def set_attr(self, attr):
        """Set memberofattr attribute"""

        self.set('memberofattr', attr)

    def get_groupattr(self):
        """Get memberofgroupattr attribute"""

        return self.get_attr_vals_utf8_l('memberofgroupattr')

    def get_groupattr_formatted(self):
        """Display memberofgroupattr attribute"""

        return self.display_attr('memberofgroupattr')

    def add_groupattr(self, attr):
        """Add memberofgroupattr attribute"""

        self.add('memberofgroupattr', attr)

    def replace_groupattr(self, attr):
        """Replace memberofgroupattr attribute"""

        self.replace('memberofgroupattr', attr)

    def remove_groupattr(self, attr):
        """Remove memberofgroupattr attribute"""

        self.remove('memberofgroupattr', attr)

    def get_allbackends(self):
        """Get memberofallbackends attribute"""

        return self.get_attr_val_utf8_l('memberofallbackends')

    def get_allbackends_formatted(self):
        """Display memberofallbackends attribute"""

        return self.display_attr('memberofallbackends')

    def enable_allbackends(self):
        """Set memberofallbackends to on"""

        self.set('memberofallbackends', 'on')

    def disable_allbackends(self):
        """Set memberofallbackends to off"""

        self.set('memberofallbackends', 'off')

    def get_skipnested(self):
        """Get memberofskipnested attribute"""

        return self.get_attr_val_utf8_l('memberofskipnested')

    def get_skipnested_formatted(self):
        """Display memberofskipnested attribute"""

        return self.display_attr('memberofskipnested')

    def enable_skipnested(self):
        """Set memberofskipnested to on"""

        self.set('memberofskipnested', 'on')

    def disable_skipnested(self):
        """Set memberofskipnested to off"""

        self.set('memberofskipnested', 'off')

    def get_autoaddoc(self):
        """Get memberofautoaddoc attribute"""

        return self.get_attr_val_utf8_l('memberofautoaddoc')

    def get_autoaddoc_formatted(self):
        """Display memberofautoaddoc attribute"""

        return self.display_attr('memberofautoaddoc')

    def set_autoaddoc(self, object_class):
        """Set memberofautoaddoc attribute"""

        self.set('memberofautoaddoc', object_class)

    def remove_autoaddoc(self):
        """Remove all memberofautoaddoc attributes"""

        self.remove_all('memberofautoaddoc')

    def get_entryscope(self, formatted=False):
        """Get memberofentryscope attributes"""

        return self.get_attr_vals_utf8_l('memberofentryscope')

    def get_entryscope_formatted(self):
        """Display memberofentryscope attributes"""

        return self.display_attr('memberofentryscope')

    def add_entryscope(self, attr):
        """Add memberofentryscope attribute"""

        self.add('memberofentryscope', attr)

    def remove_entryscope(self, attr):
        """Remove memberofentryscope attribute"""

        self.remove('memberofentryscope', attr)

    def remove_all_entryscope(self):
        """Remove all memberofentryscope attributes"""

        self.remove_all('memberofentryscope')

    def get_excludescope(self):
        """Get memberofentryscopeexcludesubtree attributes"""

        return self.get_attr_vals_utf8_l('memberofentryscopeexcludesubtree')

    def get_excludescope_formatted(self):
        """Display memberofentryscopeexcludesubtree attributes"""

        return self.display_attr('memberofentryscopeexcludesubtree')

    def add_excludescope(self, attr):
        """Add memberofentryscopeexcludesubtree attribute"""

        self.add('memberofentryscopeexcludesubtree', attr)

    def remove_excludescope(self, attr):
        """Remove memberofentryscopeexcludesubtree attribute"""

        self.remove('memberofentryscopeexcludesubtree', attr)

    def remove_all_excludescope(self):
        """Remove all memberofentryscopeexcludesubtree attributes"""

        self.remove_all('memberofentryscopeexcludesubtree')

    def get_configarea(self):
        """Get nsslapd-pluginConfigArea attribute"""

        return self.get_attr_val_utf8_l('nsslapd-pluginConfigArea')

    def set_configarea(self, attr):
        """Set nsslapd-pluginConfigArea attribute"""

        return self.set('nsslapd-pluginConfigArea', attr)

    def remove_configarea(self):
        """Remove nsslapd-pluginConfigArea attribute"""

        return self.remove_all('nsslapd-pluginConfigArea')

    def fixup(self, basedn, _filter=None):
        """Create a memberOf task

        :param basedn: Basedn to fix up
        :type basedn: str
        :param _filter: a filter for entries to fix up
        :type _filter: str

        :returns: an instance of Task(DSLdapObject)
        """

        task = tasks.MemberOfFixupTask(self._instance)
        task_properties = {'basedn': basedn}
        if _filter is not None:
            task_properties['filter'] = _filter
        task.create(properties=task_properties)

        return task


class MemberOfSharedConfig(DSLdapObject):
    """An instance of MemberOf config entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn):
        super(MemberOfSharedConfig, self).__init__(instance, dn)
        self._dn = dn
        self._rdn_attribute = 'cn'
        self._must_attributes = ['cn', 'memberOfGroupAttr', 'memberOfAttr']
        self._create_objectclasses = ['top', 'extensibleObject']
        self._protected = False
        self._exit_code = None


class RetroChangelogPlugin(Plugin):
    """An instance of Retro Changelog plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn="cn=Retro Changelog Plugin,cn=plugins,cn=config"):
        super(RetroChangelogPlugin, self).__init__(instance, dn)


class ClassOfServicePlugin(Plugin):
    """An instance of Class of Service plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn="cn=Class of Service,cn=plugins,cn=config"):
        super(ClassOfServicePlugin, self).__init__(instance, dn)


class ViewsPlugin(Plugin):
    """An instance of Views plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn="cn=Views,cn=plugins,cn=config"):
        super(ViewsPlugin, self).__init__(instance, dn)


class SevenBitCheckPlugin(Plugin):
    """An instance of addn plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn="cn=7-bit check,cn=plugins,cn=config"):
        super(SevenBitCheckPlugin, self).__init__(instance, dn)


class AccountUsabilityPlugin(Plugin):
    """An instance of Account Usability plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn="cn=Account Usability Plugin,cn=plugins,cn=config"):
        super(AccountUsabilityPlugin, self).__init__(instance, dn)


class AutoMembershipPlugin(Plugin):
    """An instance of Auto Membership plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    _plugin_properties = {
        'cn' : 'Auto Membership Plugin',
        'nsslapd-pluginEnabled' : 'off',
        'nsslapd-pluginPath' : 'libautomember-plugin',
        'nsslapd-pluginInitfunc' : 'automember_init',
        'nsslapd-pluginType' : 'betxnpreoperation',
        'nsslapd-plugin-depends-on-type' : 'database',
        'nsslapd-pluginId' : 'Auto Membership',
        'nsslapd-pluginVendor' : '389 Project',
        'nsslapd-pluginVersion' : '1.3.7.0',
        'nsslapd-pluginDescription' : 'Auto Membership plugin',
    }

    def __init__(self, instance, dn="cn=Auto Membership Plugin,cn=plugins,cn=config"):
        super(AutoMembershipPlugin, self).__init__(instance, dn)

    def fixup(self, basedn, _filter=None):
        """Create an automember rebuild membership task

        :param basedn: Basedn to fix up
        :type basedn: str
        :param _filter: a filter for entries to fix up
        :type _filter: str

        :returns: an instance of Task(DSLdapObject)
        """

        task = tasks.AutomemberRebuildMembershipTask(self._instance)
        task_properties = {'basedn': basedn}
        if _filter is not None:
            task_properties['filter'] = _filter
        task.create(properties=task_properties)

        return task


class AutoMembershipDefinition(DSLdapObject):
    """A single instance of Auto Membership Plugin config entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn=None):
        super(AutoMembershipDefinition, self).__init__(instance, dn)
        self._rdn_attribute = 'cn'
        self._must_attributes = ['cn', 'autoMemberScope', 'autoMemberFilter', 'autoMemberGroupingAttr']
        self._create_objectclasses = ['top', 'AutoMemberDefinition']
        self._protected = False

    def get_groupattr(self):
        """Get autoMemberGroupingAttr attributes"""

        return self.get_attr_vals_utf8('autoMemberGroupingAttr')

    def set_groupattr(self, attr):
        """Set autoMemberGroupingAttr attribute"""

        self.set('autoMemberGroupingAttr', attr)

    def get_defaultgroup(self, attr):
        """Get autoMemberDefaultGroup attributes"""

        return self.get_attr_vals_utf8('autoMemberDefaultGroup')

    def set_defaultgroup(self, attr):
        """Set autoMemberDefaultGroup attribute"""

        self.set('autoMemberDefaultGroup', attr)  

    def get_scope(self, attr):
        """Get autoMemberScope attributes"""

        return self.get_attr_vals_utf8('autoMemberScope')

    def set_scope(self, attr):
        """Set autoMemberScope attribute"""

        self.set('autoMemberScope', attr)

    def get_filter(self, attr):
        """Get autoMemberFilter attributes"""

        return self.get_attr_vals_utf8('autoMemberFilter')

    def set_filter(self, attr):
        """Set autoMemberFilter attributes"""

        self.set('autoMemberFilter', attr)


class AutoMembershipDefinitions(DSLdapObjects):
    """A DSLdapObjects entity which represents Auto Membership Plugin config entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param basedn: Base DN for all account entries below
    :type basedn: str
    """

    def __init__(self, instance, basedn="cn=Auto Membership Plugin,cn=plugins,cn=config"):
        super(AutoMembershipDefinitions, self).__init__(instance)
        self._objectclasses = ['top', 'autoMemberDefinition']
        self._filterattrs = ['cn']
        self._childobject = AutoMembershipDefinition
        self._basedn = basedn


class ContentSynchronizationPlugin(Plugin):
    """A single instance of Content Synchronization plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn="cn=Content Synchronization,cn=plugins,cn=config"):
        super(ContentSynchronizationPlugin, self).__init__(instance, dn)


class DereferencePlugin(Plugin):
    """A single instance of deref plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn="cn=deref,cn=plugins,cn=config"):
        super(DereferencePlugin, self).__init__(instance, dn)


class HTTPClientPlugin(Plugin):
    """A single instance of HTTP Client plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn="cn=HTTP Client,cn=plugins,cn=config"):
        super(HTTPClientPlugin, self).__init__(instance, dn)


class LinkedAttributesPlugin(Plugin):
    """A single instance of Linked Attributes plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn="cn=Linked Attributes,cn=plugins,cn=config"):
        super(LinkedAttributesPlugin, self).__init__(instance, dn)

    def fixup(self, basedn, _filter=None):
        """Create a fixup linked attributes task

        :param basedn: Basedn to fix up
        :type basedn: str
        :param _filter: a filter for entries to fix up
        :type _filter: str

        :returns: an instance of Task(DSLdapObject)
        """

        task = tasks.FixupLinkedAttributesTask(self._instance)
        task_properties = {'basedn': basedn}
        if _filter is not None:
            task_properties['filter'] = _filter
        task.create(properties=task_properties)

        return task


class LinkedAttributesConfig(DSLdapObject):
    """A single instance of Linked Attributes Plugin config entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn=None):
        super(LinkedAttributesConfig, self).__init__(instance, dn)
        self._rdn_attribute = 'cn'
        self._must_attributes = ['cn']
        self._create_objectclasses = ['top', 'extensibleObject']
        self._protected = False


class LinkedAttributesConfigs(DSLdapObjects):
    """A DSLdapObjects entity which represents Linked Attributes Plugin config entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param basedn: Base DN for all account entries below
    :type basedn: str
    """

    def __init__(self, instance, basedn="cn=Linked Attributes,cn=plugins,cn=config"):
        super(LinkedAttributesConfigs, self).__init__(instance)
        self._objectclasses = ['top', 'extensibleObject']
        self._filterattrs = ['cn']
        self._childobject = LinkedAttributesConfig
        self._basedn = basedn


class PassThroughAuthenticationPlugin(Plugin):
    """A single instance of Pass Through Authentication plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn="cn=Pass Through Authentication,cn=plugins,cn=config"):
        super(PassThroughAuthenticationPlugin, self).__init__(instance, dn)


class USNPlugin(Plugin):
    """A single instance of USN (Update Sequence Number) plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    _plugin_properties = {
        'cn' : 'USN',
        'nsslapd-pluginEnabled': 'off',
        'nsslapd-pluginPath': 'libusn-plugin',
        'nsslapd-pluginInitfunc': 'usn_init',
        'nsslapd-pluginType': 'object',
        'nsslapd-pluginbetxn': 'on',
        'nsslapd-plugin-depends-on-type': 'database',
        'nsslapd-pluginId': 'USN',
        'nsslapd-pluginVendor': '389 Project',
        'nsslapd-pluginVersion': '1.3.7.0',
        'nsslapd-pluginDescription': 'USN (Update Sequence Number) plugin',
    }

    def __init__(self, instance, dn="cn=USN,cn=plugins,cn=config"):
        super(USNPlugin, self).__init__(instance, dn)
        self._create_objectclasses.extend(['extensibleObject'])

    def is_global_mode_set(self):
        """Return True if nsslapd-entryusn-global is set to on, else False"""

        return self._instance.config.get_attr_val_utf8('nsslapd-entryusn-global') == 'on'

    def enable_global_mode(self):
        """Set nsslapd-entryusn-global to on"""

        self._instance.config.set('nsslapd-entryusn-global', 'on')

    def disable_global_mode(self):
        """Set nsslapd-entryusn-global to off"""

        self._instance.config.set('nsslapd-entryusn-global', 'off')

    def cleanup(self, suffix=None, backend=None, max_usn=None):
        """Create a USN tombstone cleanup task

        :param basedn: Basedn to fix up
        :type basedn: str
        :param _filter: a filter for entries to fix up
        :type _filter: str

        :returns: an instance of Task(DSLdapObject)
        """

        task = tasks.USNTombstoneCleanupTask(self._instance)
        task_properties = {}

        if suffix is not None:
            task_properties['suffix'] = suffix
        if backend is not None:
            task_properties['backend'] = backend
        if max_usn is not None:
            task_properties['maxusn_to_delete'] = str(max_usn)

        task.create(properties=task_properties)

        return task


class WhoamiPlugin(Plugin):
    """A single instance of whoami plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    _plugin_properties = {
        'cn' : 'whoami',
        'nsslapd-pluginEnabled' : 'on',
        'nsslapd-pluginPath' : 'libwhoami-plugin',
        'nsslapd-pluginInitfunc' : 'whoami_init',
        'nsslapd-pluginType' : 'extendedop',
        'nsslapd-plugin-depends-on-type' : 'database',
        'nsslapd-pluginId' : 'ldapwhoami-plugin',
        'nsslapd-pluginVendor' : '389 Project',
        'nsslapd-pluginVersion' : '1.3.6',
        'nsslapd-pluginDescription' : 'Provides whoami extended operation',
    }

    def __init__(self, instance, dn="cn=whoami,cn=plugins,cn=config"):
        super(WhoamiPlugin, self).__init__(instance, dn)


class RootDNAccessControlPlugin(Plugin):
    """A single instance of RootDN Access Control plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    _plugin_properties = {
        'cn' : 'RootDN Access Control',
        'nsslapd-pluginEnabled' : 'off',
        'nsslapd-pluginPath' : 'librootdn-access-plugin',
        'nsslapd-pluginInitfunc' : 'rootdn_init',
        'nsslapd-pluginType' : 'internalpreoperation',
        'nsslapd-plugin-depends-on-type' : 'database',
        'nsslapd-pluginId' : 'RootDN Access Control',
        'nsslapd-pluginVendor' : '389 Project',
        'nsslapd-pluginVersion' : '1.3.6',
        'nsslapd-pluginDescription' : 'RootDN Access Control plugin',
    }

    def __init__(self, instance, dn="cn=RootDN Access Control,cn=plugins,cn=config"):
        super(RootDNAccessControlPlugin, self).__init__(instance, dn)
        self._create_objectclasses.extend(['rootDNPluginConfig'])

    def get_open_time(self):
        """Get rootdn-open-time attribute"""

        return self.get_attr_val_utf8('rootdn-open-time')

    def get_open_time_formatted(self):
        """Display rootdn-open-time attribute"""

        return self.display_attr('rootdn-open-time')

    def set_open_time(self, attr):
        """Set rootdn-open-time attribute"""

        self.set('rootdn-open-time', attr)

    def remove_open_time(self):
        """Remove all rootdn-open-time attributes"""

        self.remove_all('rootdn-open-time')

    def get_close_time(self):
        """Get rootdn-close-time attribute"""

        return self.get_attr_val_utf8('rootdn-close-time')

    def get_close_time_formatted(self):
        """Display rootdn-close-time attribute"""

        return self.display_attr('rootdn-close-time')

    def set_close_time(self, attr):
        """Set rootdn-close-time attribute"""

        self.set('rootdn-close-time', attr)

    def remove_close_time(self):
        """Remove all rootdn-close-time attributes"""

        self.remove_all('rootdn-close-time')

    def get_days_allowed(self):
        """Get rootdn-days-allowed attribute"""

        return self.get_attr_val_utf8('rootdn-days-allowed')

    def get_days_allowed_formatted(self):
        """Display rootdn-days-allowed attribute"""

        return self.display_attr('rootdn-days-allowed')

    def set_days_allowed(self, attr):
        """Set rootdn-days-allowed attribute"""

        self.set('rootdn-days-allowed', attr)

    def remove_days_allowed(self):
        """Remove all rootdn-days-allowed attributes"""

        self.remove_all('rootdn-days-allowed')

    def add_allow_day(self, day):
        """Add a value to rootdn-days-allowed attribute"""

        days = self.get_days_allowed()
        if days is None:
            days = ""
        days = self.add_day_to_days(days, day)
        if days:
            self.set_days_allowed(days)
        else:
            self.remove_days_allowed()

    def remove_allow_day(self, day):
        """Remove a value from rootdn-days-allowed attribute"""

        days = self.get_days_allowed()
        if days is None:
            days = ""
        days = self.remove_day_from_days(days, day)
        if days:
            self.set_days_allowed(days)
        else:
            self.remove_days_allowed()

    def get_allow_host(self):
        """Get rootdn-allow-host attribute"""

        return self.get_attr_val_utf8('rootdn-allow-host')

    def get_allow_host_formatted(self):
        """Display rootdn-allow-host attribute"""

        return self.display_attr('rootdn-allow-host')

    def add_allow_host(self, attr):
        """Add rootdn-allow-host attribute"""

        self.add('rootdn-allow-host', attr)

    def remove_allow_host(self, attr):
        """Remove rootdn-allow-host attribute"""

        self.remove('rootdn-allow-host', attr)

    def remove_all_allow_host(self):
        """Remove all rootdn-allow-host attributes"""

        self.remove_all('rootdn-allow-host')

    def get_deny_host(self):
        """Get rootdn-deny-host attribute"""

        return self.get_attr_val_utf8('rootdn-deny-host')

    def get_deny_host_formatted(self):
        """Display rootdn-deny-host attribute"""

        return self.display_attr('rootdn-deny-host')

    def add_deny_host(self, attr):
        """Add rootdn-deny-host attribute"""

        self.add('rootdn-deny-host', attr)

    def remove_deny_host(self, attr):
        """Remove rootdn-deny-host attribute"""

        self.remove('rootdn-deny-host', attr)

    def remove_all_deny_host(self):
        """Remove all rootdn-deny-host attribute"""

        self.remove_all('rootdn-deny-host')

    def get_allow_ip(self):
        """Get rootdn-allow-ip attribute"""

        return self.get_attr_val_utf8('rootdn-allow-ip')

    def get_allow_ip_formatted(self):
        """Display rootdn-allow-ip attribute"""

        return self.display_attr('rootdn-allow-ip')

    def add_allow_ip(self, attr):
        """Add rootdn-allow-ip attribute"""

        self.add('rootdn-allow-ip', attr)

    def remove_allow_ip(self, attr):
        """Remove rootdn-allow-ip attribute"""

        self.remove('rootdn-allow-ip', attr)

    def remove_all_allow_ip(self):
        """Remove all rootdn-allow-ip attribute"""

        self.remove_all('rootdn-allow-ip')

    def get_deny_ip(self):
        """Remove all rootdn-deny-ip attribute"""

        return self.get_attr_val_utf8('rootdn-deny-ip')

    def get_deny_ip_formatted(self):
        """Display rootdn-deny-ip attribute"""

        return self.display_attr('rootdn-deny-ip')

    def add_deny_ip(self, attr):
        """Add rootdn-deny-ip attribute"""

        self.add('rootdn-deny-ip', attr)

    def remove_deny_ip(self, attr):
        """Remove rootdn-deny-ip attribute"""

        self.remove('rootdn-deny-ip', attr)

    def remove_all_deny_ip(self):
        """Remove all rootdn-deny-ip attribute"""

        self.remove_all('rootdn-deny-ip')

    @staticmethod
    def add_day_to_days(string_of_days, day):
        """Append a day in a string of comma separated days and return the string.
        If day already exists in the string, return processed string.

        Keyword arguments:
        string_of_days -- a string of comma seperated days
                          examples:
                              Mon
                              Tue, Wed, Thu
        day            -- a day, e.g. Mon, Tue, etc.
        """

        days = [i.strip() for i in string_of_days.split(',') if i]

        if not day in days:
            days.append(day)

        return ", ".join(days)

    @staticmethod
    def remove_day_from_days(string_of_days, day):
        """Remove a day from a string of comma separated days and return the string.
        If day does not exists in the string, return processed string.

        Keyword arguments:
        string_of_days -- a string of comma seperated days
                          examples:
                              Mon
                              Tue, Wed, Thu
        day            -- a day, e.g. Mon, Tue, etc.
        """

        days = [i.strip() for i in string_of_days.split(',') if i]

        if day in days:
            days.remove(day)

        return ", ".join(days)


class LDBMBackendPlugin(Plugin):
    """A single instance of ldbm database plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn="cn=ldbm database,cn=plugins,cn=config"):
        super(LDBMBackendPlugin, self).__init__(instance, dn)


class ChainingBackendPlugin(Plugin):
    """A single instance of chaining database plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn="cn=chaining database,cn=plugins,cn=config"):
        super(ChainingBackendPlugin, self).__init__(instance, dn)


class AccountPolicyPlugin(Plugin):
    """A single instance of Account Policy plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn="cn=Account Policy Plugin,cn=plugins,cn=config"):
        super(AccountPolicyPlugin, self).__init__(instance, dn)


class AccountPolicyConfig(DSLdapObject):
    """A single instance of Account Policy Plugin config entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn=None):
        super(AccountPolicyConfig, self).__init__(instance, dn)
        self._rdn_attribute = 'cn'
        self._must_attributes = ['cn']
        self._create_objectclasses = ['top', 'extensibleObject']
        self._protected = False


class AccountPolicyConfigs(DSLdapObjects):
    """A DSLdapObjects entity which represents Account Policy Plugin config entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param basedn: Base DN for all account entries below
    :type basedn: str
    """

    def __init__(self, instance, basedn="cn=Account Policy Plugin,cn=plugins,cn=config"):
        super(AccountPolicyConfigs, self).__init__(instance)
        self._objectclasses = ['top', 'extensibleObject']
        self._filterattrs = ['cn']
        self._childobject = AccountPolicyConfig
        self._basedn = basedn


class DNAPlugin(Plugin):
    """A single instance of Distributed Numeric Assignment plugin entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn="cn=Distributed Numeric Assignment Plugin,cn=plugins,cn=config"):
        super(DNAPlugin, self).__init__(instance, dn)


class DNAPluginConfig(DSLdapObject):
    """A single instance of DNA Plugin config entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param dn: Entry DN
    :type dn: str
    """

    def __init__(self, instance, dn=None):
        super(DNAPluginConfig, self).__init__(instance, dn)
        self._rdn_attribute = 'cn'
        self._must_attributes = ['cn']
        self._create_objectclasses = ['top', 'dnaPluginConfig']
        self._protected = False


class DNAPluginConfigs(DSLdapObjects):
    """A DSLdapObjects entity which represents DNA Plugin config entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param basedn: Base DN for all account entries below
    :type basedn: str
    """

    def __init__(self, instance, basedn="cn=Distributed Numeric Assignment Plugin,cn=plugins,cn=config"):
        super(DNAPluginConfigs, self).__init__(instance)
        self._objectclasses = ['top', 'dnaPluginConfig']
        self._filterattrs = ['cn']
        self._childobject = DNAPluginConfig
        self._basedn = basedn


class Plugins(DSLdapObjects):
    """A DSLdapObjects entity which represents MEP config entry

    :param instance: An instance
    :type instance: lib389.DirSrv
    :param basedn: Base DN for all account entries below
    :type basedn: str
    """

    # This is a map of plugin to type, so when we
    # do a get / list / create etc, we can map to the correct
    # instance.
    def __init__(self, instance, basedn=None):
        super(Plugins, self).__init__(instance=instance)
        self._objectclasses = ['top', 'nsslapdplugin']
        self._filterattrs = ['cn', 'nsslapd-pluginPath']
        self._childobject = Plugin
        self._basedn = 'cn=plugins,cn=config'
        # This is used to allow entry to instance to work
        self._list_attrlist = ['dn', 'nsslapd-pluginPath']
        # This may not work for attr unique which can have many instance ....
        # Should we be doing this from the .so name?
        self._pluginmap = {
            'libaddn-plugin' : AddnPlugin,
            'libattr-unique-plugin' : AttributeUniquenessPlugin,
            'liblst-plugin' : LdapSSOTokenPlugin,
            'libmanagedentries-plugin' : ManagedEntriesPlugin,
            'libreferint-plugin' : ReferentialIntegrityPlugin,
        }

    def _entry_to_instance(self, dn=None, entry=None):
        # If dn in self._pluginmap
        if entry['nsslapd-pluginPath'] in self._pluginmap:
            return self._pluginmap[entry['nsslapd-pluginPath']](self._instance, dn=dn)
        else:
            return super(Plugins, self)._entry_to_instance(dn)

    # To maintain compatibility with plugin's legacy, here are some helpers.
    def enable(self, name=None, plugin_dn=None):
        """Set nsslapd-pluginEnabled to on"""

        if plugin_dn is not None:
            raise ValueError('You should swap to the new Plugin API!')
        if name is None:
            raise ldap.NO_SUCH_OBJECT('Must provide a selector for name')
        plugin = self.get(selector=name)
        plugin.enable()

    def disable(self, name=None, plugin_dn=None):
        """Set nsslapd-pluginEnabled to off"""

        if plugin_dn is not None:
            raise ValueError('You should swap to the new Plugin API!')
        if name is None:
            raise ldap.NO_SUCH_OBJECT('Must provide a selector for name')
        plugin = self.get(selector=name)
        plugin.disable()


class PluginsLegacy(object):

    proxied_methods = 'search_s getEntry'.split()

    def __init__(self, conn):
        """@param conn - a DirSrv instance"""
        self.conn = conn
        self.log = conn.log

    def __getattr__(self, name):
        if name in Plugins.proxied_methods:
            from lib389 import DirSrv
            return DirSrv.__getattr__(self.conn, name)

    def list(self, name=None):
        '''
            Returns a search result of the plugins entries with all their
            attributes

            If 'name' is not specified, it returns all the plugins, else it
            returns the plugin matching ('cn=<name>, DN_PLUGIN')

            @param name - name of the plugin

            @return plugin entries

            @raise None

        '''

        if name:
            filt = "(objectclass=%s)" % PLUGINS_OBJECTCLASS_VALUE
            base = "cn=%s,%s" % (name, DN_PLUGIN)
            scope = ldap.SCOPE_BASE
        else:
            filt = "(objectclass=%s)" % PLUGINS_OBJECTCLASS_VALUE
            base = DN_PLUGIN
            scope = ldap.SCOPE_ONELEVEL

        ents = self.conn.search_s(base, scope, filt)
        return ents

    def enable(self, name=None, plugin_dn=None):
        '''
            Enable a plugin

            If 'plugin_dn' and 'name' are provided, plugin_dn is used and
            'name' is not considered

            @param name - name of the plugin
            @param plugin_dn - DN of the plugin

            @return None

            @raise ValueError - if 'name' or 'plugin_dn' lead to unknown plugin
                   InvalidArgumentError - if 'name' and 'plugin_dn' are missing
        '''

        dn = plugin_dn or "cn=%s,%s" % (name, DN_PLUGIN)
        filt = "(objectclass=%s)" % PLUGINS_OBJECTCLASS_VALUE

        if not dn:
            from lib389 import InvalidArgumentError
            raise InvalidArgumentError("'name' and 'plugin_dn' are missing")

        ents = self.conn.search_s(dn, ldap.SCOPE_BASE, filt)
        if len(ents) != 1:
            raise ValueError("%s is unknown")

        self.conn.modify_s(dn, [(ldap.MOD_REPLACE,
                                 PLUGIN_PROPNAME_TO_ATTRNAME[PLUGIN_ENABLE],
                                 PLUGINS_ENABLE_ON_VALUE)])

    def disable(self, name=None, plugin_dn=None):
        '''
            Disable a plugin

            If 'plugin_dn' and 'name' are provided, plugin_dn is used and
            'name' is not considered

            @param name - name of the plugin
            @param plugin_dn - DN of the plugin

            @return None

            @raise ValueError - if 'name' or 'plugin_dn' lead to unknown plugin
                InvalidArgumentError - if 'name' and 'plugin_dn' are missing
        '''

        dn = plugin_dn or "cn=%s,%s" % (name, DN_PLUGIN)
        filt = "(objectclass=%s)" % PLUGINS_OBJECTCLASS_VALUE

        if not dn:
            from lib389 import InvalidArgumentError
            raise InvalidArgumentError("'name' and 'plugin_dn' are missing")

        ents = self.conn.search_s(dn, ldap.SCOPE_BASE, filt)
        if len(ents) != 1:
            raise ValueError("%s is unknown")

        self.conn.modify_s(dn, [(ldap.MOD_REPLACE,
                                 PLUGIN_PROPNAME_TO_ATTRNAME[PLUGIN_ENABLE],
                                 PLUGINS_ENABLE_OFF_VALUE)])