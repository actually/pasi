from config import config

class Validation:
    """ Various methods for input validation. """

    @staticmethod
    def checkAuth(auth_token):
        """ Verify that submitted token matches. """
        if (auth_token != config.token):
            raise Exception("Authentication Failed")

    @staticmethod
    def checkP4Port(p4_port):
        """ Check that submitted p4 port is included in the valid list. """
        if p4_port not in config.valid_p4_ports:
            raise Exception("Invalid Server")

    @staticmethod
    def checkGroup(group):
        """ Make sure protected groups can not be modified. """
        if group in config.protected_groups:
            raise Exception("Protected group " + group + \
                            " can not be modified")

    @staticmethod
    def checkUser(user):
        """ Make sure protected users can no be modified. """
        if user in config.protected_users:
            raise Exception("Protected user " + user + \
                            " can not be modified")
