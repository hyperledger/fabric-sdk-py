# SPDX-License-Identifier: Apache-2.0

import logging

consoleHandler = logging.StreamHandler()
_logger = logging.getLogger(__name__)

_logger.setLevel(logging.DEBUG)
_logger.addHandler(consoleHandler)


class Contract(object):
    """Represents a smart contract (chaincode) instance in a network.
    Applications should get a Contract instance using the
    networks's get_contract method.
    :return: an instance of Contract
    """

    def __init__(self, network, cc_name, gateway):
        self.network = network
        self.channel = network.channel
        self.cc_name = cc_name
        self.gatetway = gateway

    def get_network(self):
        return self.network

    def get_cc_name(self):
        return self.cc_name

    def get_options(self):
        return self.gateway.get_options()

    # TODO: Remove requestor and integrate with wallet from Gateway
    async def submit_transaction(self, name, args, requestor):
        """
        Submit a transaction to the ledger. The transaction function will be
        evaluated on the list of peers discovered and then submitted to the ordering service
        for committing to the ledger.
        """
        channel_name = self.network.channel.name
        cli = self.gatetway.client
        peers = cli._peers

        response = await cli.chaincode_invoke(requestor=requestor,
                                              channel_name=channel_name,
                                              peers=peers,
                                              args=args,
                                              cc_name=self.cc_name,
                                              wait_for_event=True)

        return response

    # TODO: Remove requestor and integrate with wallet from Gateway
    async def evaluate_transaction(self, name, args, requestor):
        """
        Evaluate a transaction function and return its results.
        The transaction function will be evaluated on
        the endorsing peers but the responses will not be sent to
        the ordering service and hence will not be committed to the ledger.
        This is used for querying the world state.
        """
        channel_name = self.network.channel.name
        cli = self.gatetway.client
        peers = cli._peers

        response = await cli.chaincode_query(requestor=requestor,
                                             channel_name=channel_name,
                                             peers=peers,
                                             args=args,
                                             cc_name=self.cc_name)
        return response
