# -*- coding: utf-8 -*-
"""
gites.ldap

Licensed under the GPL license, see LICENCE.txt for more details.
Copyright by Affinitic sprl

$Id: event.py 67630 2006-04-27 00:54:03Z jfroche $
"""
from Products.PloneLDAP.factory import genericPluginCreation
from Products.PloneLDAP.plugins.ldap import PloneLDAPMultiPlugin
from Products.CMFCore.utils import getToolByName
import logging
logger = logging.getLogger('gites.core')


def setupgites(context):
    if context.readDataFile('gites.ldap_various.txt') is None:
        return
    logger.debug('Setup gites ldap')
    portal = context.getSite()
    addRoles(portal)
    activatePloneLDAPPlugin(portal)
    addMemberProperty(portal)


def addMemberProperty(portal):
    """
    Add the property which is mapped between ldap & plone
    """
    md = getToolByName(portal, 'portal_memberdata')
    if not md.hasProperty('pk'):
        md.manage_addProperty('pk', '', 'string')


def addRoles(portal):
    """
    Add the default roles
    """
    portalrolemgr = portal.acl_users.portal_role_manager
    roleIds = portalrolemgr.listRoleIds()
    if 'Proprietaire' not in roleIds:
        portalrolemgr.addRole('Proprietaire')
    data = list(portal.__ac_roles__)
    for role in ['Proprietaire']:
        if not role in data:
            data.append(role)
    portal.__ac_roles__ = tuple(data)


def activatePloneLDAPPlugin(portal):
    """
    Go in the acl and active our plugin
    """
    acl = portal.acl_users
    if 'ldap' not in acl.objectIds():
        luf=genericPluginCreation(acl, PloneLDAPMultiPlugin, id='ldap',
                title='LDAP Connexion', login_attr='cn', uid_attr='cn',
                users_base="dc=gitesdewallonie,dc=net",
                users_scope=2, roles="Member",
                groups_base="ou=groups,dc=gitesdewallonie,dc=net",
                groups_scope=2, binduid="cn=admin,dc=gitesdewallonie,dc=net",
                bindpwd='phoneph0ne',
                binduid_usage=1, rdn_attr='cn',
                obj_classes='person,organizationalPerson,gites-proprietaire',
                local_groups=0, use_ssl=0, encryption='SHA',
                read_only=0, LDAP_server="localhost", REQUEST=None)

        luf.manage_addLDAPSchemaItem("registeredAddress", "email",
                                     public_name="email")
        luf.manage_addLDAPSchemaItem("title", "fullname",
                                     public_name="fullname")
        luf.manage_addLDAPSchemaItem("pk", "pk", public_name="pk")

        luf.manage_addGroupMapping("Proprietaire", "Proprietaire")

    interfaces = ['IAuthenticationPlugin',
                  'ICredentialsResetPlugin',
                  'IGroupEnumerationPlugin',
                  'IGroupIntrospection',
                  'IGroupManagement',
                  'IGroupsPlugin',
                  'IPropertiesPlugin',
                  'IRoleEnumerationPlugin',
                  'IRolesPlugin',
                  'IUserAdderPlugin',
                  'IUserEnumerationPlugin',
                  'IUserManagement']
    ldap = getattr(acl, 'ldap')
    ldap.manage_activateInterfaces(interfaces)
    for interface in interfaces:
        interface_object = acl.plugins._getInterfaceFromName(interface)
        acl.plugins.movePluginsUp(interface_object, ['ldap'])
