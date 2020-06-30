# SPDX-License-Identifier: Apache-2.0

import logging

from hfc.fabric.channel.channel import Channel
from hfc.fabric_network.contract import Contract

consoleHandler = logging.StreamHandler()
_logger = logging.getLogger(__name__)

_logger.setLevel(logging.DEBUG)
_logger.addHandler(consoleHandler)


class Network(object):
    """A Network represents the set of peers in a Fabric network.
    Applications should get a Network instance using the
    gateway's getNetwork method.
    """

    def __init__(self, gateway, channel):
        """ Construct Network. """
        self.gateway = gateway
        self.channel = channel
        self.contracts = dict()
        self.initialized = False
        self.listeners = dict()
        self.discovery_enabled = False

    async def __init_internal_channel(self, discovery):
        """
        Initialize the channel if it hasn't been done
        :param discovery: must include requestor
        :return:
        """
        if discovery:
            self.discovery_enabled = True
            client = self.gateway.get_client()
            ledger_peers = client._peers
            if len(ledger_peers) == 0:
                _logger.error("No peers defined")
        else:
            if not isinstance(self.channel, Channel):
                _logger.error("network.channel should be an instance of channel")
            ledger_peers = self.channel._peers
            if len(ledger_peers) == 0:
                _logger.error("No peers defined")

        success = False

        for ledger_peer in ledger_peers:
            try:
                await self.gateway.client.init_with_discovery(discovery['requestor'],
                                                              ledger_peers[ledger_peer],
                                                              self.channel)
                success = True
                self.channel = self.gateway.client.get_channel(self.channel)
            except Exception:
                _logger.warning('Unable to initialize channel. Attempted to contact %s Peers. Last error was %s',
                                ledger_peer,
                                Exception)
            if success:
                break

    async def _initialize(self, discover=None):
        """
        Initialize this network instance
        :param discover:
        :return:
        """
        if self.initialized:
            return
        await self.__init_internal_channel(discover)
        self.initialized = True

    def get_contract(self, chaincode_id):
        if not self.initialized:
            _logger.error("Unable to get contract as network has failed to initialize")

        if chaincode_id not in self.contracts:
            contract = Contract(self, chaincode_id, self.gateway)
            self.contracts[chaincode_id] = contract

        return self.contracts[chaincode_id]
