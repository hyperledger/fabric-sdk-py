import logging

from hfc.fabric import Client

consoleHandler = logging.StreamHandler()
_logger = logging.getLogger(__name__)

_logger.setLevel(logging.DEBUG)
_logger.addHandler(consoleHandler)


class Gateway(object):
    """
    The gateway peer provides the connection point for an application to access the Fabric network.
    It can then be connected to a fabric network using the path to network profile.
    """
    def __init(self):
        self.client = None
        self.wallet = None
        self.networks = {}
        self.options = {}

    # TODO : Write function to merge options
    async def connect(self, net_profile, options):
        if 'wallet' not in options:
            _logger.error("A wallet must be assigned to a gateway instance")

        if not net_profile:
            self.client = Client()
        else:
            self.client = Client(net_profile=net_profile)

        if 'identity' in options:
            self.current_identity = self.client.get_user(org_name=options['identity']['org_name'],
                                                         name=options['identity']['name'])

    def get_current_identity(self):
        return self.current_identity

    def get_client(self):
        return self.client

    def get_options(self):
        return self.options

    # TODO : Complete this after writing Network
    def get_network(self, network_name):
        return True
