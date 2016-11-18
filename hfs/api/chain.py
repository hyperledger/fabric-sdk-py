# Copyright esse.io 2016 All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


class Chain(object):
    """
        The "Chain" object captures settings for a channel, which is created
        by the orderers to isolate transactions delivery to peers participating
        on channel.
    """

    def __init__(self):
        self.peers = []

    def add_peer(self, peer):
        """
            Add peer endpoint to a chain object

            Args:
                peer (Peer): an instance of the Peer class
        """
        self.peers.append(peer)

    def remove_peer(self, peer):
        """
            Remove peer endpoint from a chain object

            Args:
                peer (Peer): an instance of the Peer class
        """
        self.peers.remove(peer)

    def get_peers(self):
        """
            Get peers of a chain.

            Returns:
                []: The peer list on the chain
        """
        return self.peers

    def add_orderer(self, orderer):
        """
            Add orderer endpoint to a chain object.
            A chain instance may choose to use a single orderer node, which
            will broadcast requests to the rest of the orderer network. Or if
            the application does not trust the orderer nodes, it can choose to
            use more than one by adding them to the chain instance. And all
            APIs concerning the orderer will broadcast to all orderers
            simultaneously.

            Args:
                orderer (Orderer): an instance of the Orderer class
        """
        pass

    def remove_orderer(self, orderer):
        """
            Remove orderer endpoint from a chain object.

            Args:
                orderer (Orderer): an instance of the Orderer class
        """
        pass

    def get_orderers(self):
        """
            Get orderers of a chain.

            Returns:
                []: The orderer list on the chain
        """
        pass

    def initialize(self):
        """
            Calls the orderer(s) to start building the new chain, which is a
            combination of opening new message stream and connecting the list
            of participating peers.

            Returns:
                bool: True if the chain initialization process was successful,
                False otherwise.
        """
        pass

    def is_readonly(self):
        """
            Get chain status to see if the underlying channel has been
            terminated, making it a read-only chain, where information
            (transactions and states) can be queried but no new transactions
            can be submitted.

            Returns:
                bool: True if the chain is read-only, False otherwise.
        """
        pass

    def get_event_hub(self):
        """
            Get the eventHub for this chain.

            Returns:
                eventHub (EventHub instance): The active eventHub for this
                chain.
        """
        pass

    def event_hub_connect(self, address):
        """
            Create and connect the eventHub for this chain.

            Args:
                address (str): Peer address for event source
        """
        pass

    def event_hub_disconnect(self):
        """
            Disconnect the eventHub for this chain.
        """
        pass

    def query_info(self):
        """
            Queries for various useful information on the state of the Chain
            (height, known peers).

            Returns:
                chainInfo (ChainInfo) with height, currently the only useful
                info.
        """
        pass

    def query_block(self):
        """
            Queries the ledger for Block by block number.

            Return:
                long: block number.
        """
        pass

    def query_transaction(self, transactionID):
        """
            Queries the ledger for Transaction by transaction ID.

            Args:
                transactionID (str): transaction ID

            Returns:
                TransactionInfo containing the transaction
        """
        pass
