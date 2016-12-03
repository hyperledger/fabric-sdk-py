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
    """ The Chain Object

    The "Chain" object captures settings for a channel, which is created
    by the orderers to isolate transactions delivery to peers participating
    on channel.
    """

    def __init__(self):
        self.peers = []
        self.keyValStore = None
        self.tcertBatchSize = 0

    def getKeyValueStore(self):
        """Get the key val store instance

        Get the KeyValueStore implementation (if any)
        that is currently associated with this chain

        :return: the current KeyValueStore associated with this chain,
            or None if not set.
        """
        return self.keyValStore

    def setKeyValueStore(self, keyValStore):
        """Set the key value store implementation

        :param keyValStore: a KeyValueStore instance
        """
        self.keyValStore = keyValStore

    def getTCertBatchSize(self):
        """Get the tcert batch size

        :return: the current tcert batch size
        """
        return self.tcertBatchSize

    def setTCertBatchSize(self, batchSize):
        """Set the tcert batch size

        :param batchSize: tcert batch size (integer)
        """
        self.tcertBatchSize = batchSize

    def add_peer(self, peer):
        """Add peer endpoint to a chain object

        :param peer: an instance of the Peer class
        """
        self.peers.append(peer)

    def remove_peer(self, peer):
        """Remove peer endpoint from a chain object

        :param peer (Peer): an instance of the Peer class
        """
        self.peers.remove(peer)

    def get_peers(self):
        """Get peers of a chain.

        :return: The peer list on the chain
        """
        return self.peers

    def add_orderer(self, orderer):
        """Add orderer endpoint to a chain object.

        A chain instance may choose to use a single orderer node, which
        will broadcast requests to the rest of the orderer network. Or if
        the application does not trust the orderer nodes, it can choose to
        use more than one by adding them to the chain instance. And all
        APIs concerning the orderer will broadcast to all orderers
        simultaneously.

        :param orderer: an instance of the Orderer class
        """
        pass

    def remove_orderer(self, orderer):
        """Remove orderer endpoint from a chain object.

        :param orderer: an instance of the Orderer class
        """
        pass

    def get_orderers(self):
        """Get orderers of a chain.

        :return: The orderer list on the chain
        """
        pass

    def initialize(self):
        """Initialize a new chain

        Calls the orderer(s) to start building the new chain, which is a
        combination of opening new message stream and connecting the list
        of participating peers.

        :return: True if the chain initialization process was successful,
            False otherwise.
        """
        pass

    def is_readonly(self):
        """Check the chain if read-only

        Get chain status to see if the underlying channel has been
        terminated, making it a read-only chain, where information
        (transactions and states) can be queried but no new transactions
        can be submitted.

        :return: True if the chain is read-only, False otherwise.
        """
        pass

    def get_event_hub(self):
        """Get the eventHub for this chain.

        :return: The active eventHub for this chain.
        """
        pass

    def event_hub_connect(self, address):
        """Create and connect the eventHub for this chain.

        :param address: Peer address (string) for event source
        """
        pass

    def event_hub_disconnect(self):
        """Disconnect the eventHub for this chain.
        """
        pass

    def query_info(self):
        """Query the information of chain

        Queries for various useful information on the state of the Chain
        (height, known peers).

        :return: :class:`ChainInfo` chaininfo with height,
            currently the only useful information.
        """
        pass

    def query_block(self):
        """Queries the ledger for Block by block number.

        :return: block number (long).
        """
        pass

    def query_transaction(self, transactionID):
        """Queries the ledger for Transaction by transaction ID.

        :param transactionID: transaction ID (string)
        :return: TransactionInfo containing the transaction
        """
        pass
