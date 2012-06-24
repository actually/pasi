from soaplib.wsgi_soap import SimpleWSGISoapApp
from soaplib.service import soapmethod
from soaplib.serializers.primitive import String
from config import config
from P4 import P4

from product.validation import Validation

from random import Random

import os
import logging
import string
import sets

log = logging.getLogger(__name__)

class PerforceBridge(SimpleWSGISoapApp):
    """ Perforce Administration SOAP Interface """

    @soapmethod(String, _returns=String)
    def getServers(self, auth_token):
	    """ Get server list from config file. """
	    Validation.checkAuth(auth_token)

	    servers = "\n".join(config.valid_p4_ports)

	    return servers

    @soapmethod(String, String, _returns=String)
    def getUsers(self, auth_token, p4_port):
        """ Get user list from server. """
        Validation.checkAuth(auth_token)
        Validation.checkP4Port(p4_port)

        p4 = P4()
        p4.port = p4_port
        p4.user = config.admin_user
        p4.connect()

        users = "\n".join(d.get('User') for d in p4.run_users())

        p4.disconnect()

        return users

    @soapmethod(String, String, String, String, String)
    def addUser(self, auth_token, user, email, fullName, p4_port):
        """ Create a new Perforce user. """
        Validation.checkAuth(auth_token)
        Validation.checkP4Port(p4_port)

        log.info("Creating user %s on port %s." % (user, p4_port))

        p4 = P4()
        p4.port = p4_port
        p4.user = config.admin_user
        p4.connect()

        randomPassword = ''.join(Random().sample(string.letters+string.digits, 12))

        p4.input = {'Email': email, 'FullName': fullName, 'Password': randomPassword, 'User':user}
        p4.run_user("-f", "-i")

        p4.disconnect()

        self._addUserToGroup(user, "users", p4_port)

    @soapmethod(String, String, String)
    def deleteUser(self, auth_token, user, p4_port):
        """ Delete a Perforce user. """
        Validation.checkAuth(auth_token)
        Validation.checkP4Port(p4_port)
        Validation.checkUser(user)

        log.info("Deleting user %s from port %s." % (user, p4_port))

        p4 = P4()
        p4.port = p4_port
        p4.user = config.admin_user
        p4.connect()

        opened = p4.run_opened("-u %s" % (user))

        # save host and client, since they will have to be changed
        p4host = p4.host
        p4client = p4.client

        # we can not delete a user unless they have no files open
        for file in opened:
            # to reopen the file, the client has to match
            # for client to match, host has to be set as well
            client = p4.fetch_client(file['client'])
            p4.client = file['client']
            p4.host = client['Host']
            p4.run_reopen(file['depotFile'])
            log.info("Taking over file: " + file['depotFile'])

        # restore host and client (for consistancy sake)
        p4.host = p4host
        p4.client = p4client

        output = p4.run_user("-f", "-d", user)

        p4.disconnect()

        self._deleteUserFromGroup(user, "users", p4_port)

    @soapmethod(String, String, _returns=String)
    def getGroups(self, auth_token, p4_port):
        """ Get group list from server. """
        Validation.checkAuth(auth_token)
        Validation.checkP4Port(p4_port)

        p4 = P4()
        p4.port = p4_port
        p4.user = config.admin_user
        p4.connect()

        groups = p4.run_groups()
        p4.disconnect()

        grouplist = []
        output = "\n"

        for group in groups:
            if group['group'] not in config.protected_groups:
                grouplist.append(group['group'])

        grouplist = list(sets.Set(grouplist))

        return output.join(grouplist)

    @soapmethod(String, String, String, String)
    def addUserToGroup(self, auth_token, user, group, p4_port):
        """ Add Perforce user to a group. """
        Validation.checkAuth(auth_token)
        Validation.checkP4Port(p4_port)
        Validation.checkUser(user)
        Validation.checkGroup(group)

        log.info("Adding user %s to group %s on port %s." % (user, group, p4_port))

        self._addUserToGroup(user, group, p4_port)

    def _addUserToGroup(self, user, group, p4_port):
        p4 = P4()
        p4.port = p4_port
        p4.user = config.admin_user
        p4.connect()

        group_data = p4.run_group("-o", group)[0]

        if 'Users' in group_data and user in group_data['Users']:
            raise Exception("User " + user + " is aleady a member of group " + group + ".")
        else:
            if 'Users' not in group_data:
                group_data['Users'] = []
            group_data['Users'].append(user)
            p4.input = group_data
            p4.run_group("-i")

        p4.disconnect()

    @soapmethod(String, String, String, String)
    def deleteUserFromGroup(self, auth_token, user, group, p4_port):
        """ Remove a Perforce user from a group. """
        Validation.checkAuth(auth_token)
        Validation.checkP4Port(p4_port)
        Validation.checkUser(user)
        Validation.checkGroup(group)
        
        log.info("Removing user %s from group %s on port %s." % (user, group, p4_port))

        self._deleteUserFromGroup(user, group, p4_port)

    def _deleteUserFromGroup(self, user, group, p4_port):
        p4 = P4()
        p4.port = p4_port
        p4.user = config.admin_user
        p4.connect()

        group_data = p4.run_group("-o", group)[0]
        if user not in group_data['Users']:
            raise Exception("User " + user + " is not a member of group " + group + ".")
        else:
            group_data['Users'].remove(user)
            p4.input = group_data
            p4.run_group("-i")

        p4.disconnect()

    @soapmethod(String, String, String, _returns=String)
    def displayGroupMemberships(self, auth_token, p4_port, user):
        """ Display group memberships for a given user. """

        Validation.checkAuth(auth_token)
        Validation.checkP4Port(p4_port)

        p4 = P4()
        p4.port = p4_port
        p4.user = config.admin_user
        p4.connect()

        groups = p4.run("groups", user)
        p4.disconnect()

        output = ""

        for group in groups:
            if group['group'] not in config.protected_groups:
                output = output + "%s\n" % (group['group'])

        return output

    @soapmethod(String, String, String, _returns=String)
    def displayPermissions(self, auth_token, group, p4_port):
        """ Displays group permissions. """
        Validation.checkAuth(auth_token)
        Validation.checkP4Port(p4_port)
        Validation.checkGroup(group)

        p4 = P4()
        p4.port = p4_port
        p4.user = config.admin_user
        p4.connect()

        protects = p4.run_protects("-g", group)

        p4.disconnect()

        output = ""

        for protect in protects:
            if protect.has_key('unmap'):
                output = output + "%s: -%s\n" % (protect['perm'], protect['depotFile'])
            else:
                output = output + "%s: %s\n" % (protect['perm'], protect['depotFile'])
        
        return output

    @soapmethod(String, String, String)
    def resetPassword(self, auth_token, user, p4_port):
        """Reset a user's Perforce password and email them a new one"""

        Validation.checkAuth(auth_token)
        Validation.checkP4Port(p4_port)

    # mailSubject needs to be a single-quoted string or os.system will parse it as multiple strings.
	mailSubject = "'Perforce password reset for %s'" % (p4_port)
	mailAddress = "CHANGME"
	mailCC = "CHANGEME"

	randomPassword = ''.join(Random().sample(string.letters+string.digits, 12))

        p4 = P4()
        p4.port = p4_port
        p4.user = config.admin_user
        p4.connect()

	"""Password reset command goes here, p4.run(blahblah)"""
    p4.run("password","-P%s" % randomPassword,"-P%s" % randomPassword,user)

	p4.disconnect()

	os.system('echo %s | mail -s %s -c %s %s' % (randomPassword,mailSubject,mailCC,mailAddress))


def run():
    from cherrypy.wsgiserver import CherryPyWSGIServer
    server = CherryPyWSGIServer(('0.0.0.0', config.soap_port), PerforceBridge())
    server.start()
