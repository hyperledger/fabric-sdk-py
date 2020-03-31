# SPDX-License-Identifier: Apache-2.0

import logging

from hfc.fabric import Client
from hfc.fabric_network.network import Network

consoleHandler = logging.StreamHandler()
_logger = logging.getLogger(__name__)

_logger.setLevel(logging.DEBUG)
_logger.addHandler(consoleHandler)


class Gateway(object):
    """
    The gateway peer provides the connection point for an application to access the Fabric network.
    It can then be connected to a fabric network using the path to network profile.
    """
    def __init__(self):
        """ Construct Gateway. """
        self.client = None
        self.wallet = None
        self.networks = dict()
        self.options = dict()

    # TODO : Write function to merge options
    async def connect(self, net_profile, options):
        """
        Connect to the Gateway with a connection profile and connection options.
        :param net_profile: Path to the Connection Profile
        :param options: Options such as wallet identity and user identity
        """
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
        """ :return The current identity being used in the gateway. """
        return self.current_identity

    def get_client(self):
        """ :retyrn Client instance. """
        return self.client

    def get_options(self):
        """ :return the options being used. """
        return self.options

    # TODO : remove requestor and integrate this with wallet and identity
    async def get_network(self, network_name, requestor):
        """
        Returns an object representing a network
        :param Name of the channel
        :param requestor: User role who issue the request
        :return: Network instance
        """
        new_network = Network(self, 'mychannel')
        await new_network._initialize({'requestor': requestor})
        self.networks[network_name] = new_network
        return new_network
