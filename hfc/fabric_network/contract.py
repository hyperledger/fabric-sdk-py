# SPDX-License-Identifier: Apache-2.0

import logging

consoleHandler = logging.StreamHandler()
_logger = logging.getLogger(__name__)

_logger.setLevel(logging.DEBUG)
_logger.addHandler(consoleHandler)


class Contract(object):
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
        channel_name = self.network.channel.name()
        peers = list(self.network.channel.peers().keys())
        cli = self.gatetway.client

        response = await cli.chaincode_invoke(requestor=requestor,
                                              channel_name=channel_name,
                                              peers=peers,
                                              args=args,
                                              cc_name=self.cc_name,
                                              wait_for_event=True)

        return response

    # TODO: Remove requestor and integrate with wallet from Gateway
    async def evaluate_transaction(self, name, args, requestor):
        channel_name = self.network.channel.name()
        peers = list(self.network.channel.peers().keys())
        cli = self.gatetway.client

        response = await cli.chaincode_query(requestor=requestor,
                                             channel_name=channel_name,
                                             peers=peers,
                                             args=args,
                                             cc_name=self.cc_name)
        return response
