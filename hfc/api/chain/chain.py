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
import logging

from hfc.api.chain.installment import chaincode_installment
from hfc.api.chain.instantiation import chaincode_instantiation
from hfc.api.chain.invocation import chaincode_invocation
from hfc.api.crypto.crypto import ecies

_logger = logging.getLogger(__name__ + ".chain")


class Chain(object):
    """ The Chain Object

    The "Chain" object captures settings for a channel, which is created
    by the orderers to isolate transactions delivery to peers participating
    on channel.
    """

    def __init__(self, name, crypto_suite=ecies(), peers=None, orderers=None,
                 key_value_store=None, tcert_batch_size=0,
                 is_dev_mode=False, is_pre_fetch_mode=False):
        """

        Args:
            name: Chain unique name
            peers: Peer set
            orderers: Orderer set
            key_value_store: A KeyValueStore instance
            tcert_batch_size: Tcert batch size
            is_dev_mode: Determines if chaincode deployment in dev mode
            is_pre_fetch_mode: Determines if pre fetch tcerts
        """
        self._orderers = {} if not orderers else orderers
        self._peers = {} if not peers else peers
        self._name = name
        self._key_value_store = key_value_store
        self._tcert_batch_size = tcert_batch_size
        self._is_dev_mode = is_dev_mode
        self._is_pre_fetch_mode = is_pre_fetch_mode
        self._crypto = crypto_suite

    @property
    def is_dev_mode(self):
        """Get is_dev_mode

        Returns: is_dev_mode

        """
        return self._is_dev_mode

    @property
    def name(self):
        """Get chain name.

        Returns: chain name
        """
        return self._name

    @property
    def key_value_store(self):
        """Get the key val store instance

        Get the KeyValueStore implementation (if any)
        that is currently associated with this chain

        Returns: the current KeyValueStore associated with this chain,
            or None if not set.
        """
        return self._key_value_store

    @key_value_store.setter
    def key_value_store(self, key_value_store):
        """Set the key value store implementation

        :param key_value_store: a KeyValueStore instance
        """
        self.key_value_store = key_value_store

    @property
    def tcert_batch_size(self):
        """Get the tcert batch size

        :return: the current tcert batch size
        """
        return self._tcert_batch_size

    @tcert_batch_size.setter
    def tcert_batch_size(self, tcert_batch_size):
        """Set the tcert batch size

        :param tcert_batch_size: tcert batch size (integer)
        """
        self._tcert_batch_size = tcert_batch_size

    def add_peer(self, peer):
        """Add peer endpoint to a chain object

        :param peer: an instance of the Peer class
        """
        self._peers[peer.endpoint] = peer

    def remove_peer(self, endpoint):
        """Remove peer endpoint from a chain object

        Args:
            endpoint(string): grpc address of the peer to remove
        """
        if endpoint in self._peers:
            self._peers.pop(endpoint, None)

    @property
    def peers(self):
        """Get peers of a chain.

        :return: The peer list on the chain
        """
        return self._peers

    def is_valid_peer(self, peer):
        """Check a peer if it is on this chain

        Returns: True/False

        """
        endpoint = peer.endpoint()
        return endpoint in self._peers

    def add_orderer(self, orderer):
        """Add orderer endpoint to a chain object.

        A chain instance may choose to use a single orderer node, which
        will broadcast requests to the rest of the orderer network. Or if
        the application does not trust the orderer nodes, it can choose to
        use more than one by adding them to the chain instance. And all
        APIs concerning the orderer will broadcast to all orderers
        simultaneously.

        Args:
             orderer: an instance of the Orderer class
        """
        pass

    def remove_orderer(self, orderer):
        """Remove orderer endpoint from a chain object.

        Args:
            orderer: an instance of the Orderer class
        """
        pass

    def get_orderers(self):
        """Get orderers of a chain.

        Returns: The orderer list on the chain
        """
        pass

    def initialize_chain(self):
        """Initialize a new chain

        Calls the orderer(s) to start building the new chain, which is a
        combination of opening new message stream and connecting the list
        of participating peers.

        :return: True if the chain initialization process was successful,
            False otherwise.
        """
        return True

    def update_chain(self):
        """Update a new chain

        Calls the orderer(s) to update an existing chain. This allows the
        addition and deletion of Peer nodes to an existing chain, as well as
        the update of Peer certificate information upon certificate renewals.

        Returns: True if the chain update process was successful,
            False otherwise.
        """
        return True

    def is_readonly(self):
        """Check the chain if read-only

        Get chain status to see if the underlying channel has been
        terminated, making it a read-only chain, where information
        (transactions and state_store) can be queried but no new transactions
        can be submitted.

        Returns: True if the chain is read-only, False otherwise.
        """
        pass

    def query_info(self):
        """Query the information of chain

        Queries for various useful information on the state of the Chain
        (height, known peers).

        Returns: :class:`ChainInfo` chaininfo with height,
            currently the only useful information.
        """
        pass

    def query_block(self):
        """Queries the ledger for Block by block number.

        Returns: block number (long).
        """
        pass

    def query_transaction(self, transactionID):
        """Queries the ledger for Transaction by transaction ID.

        Args:
            transactionID: transaction ID (string)

        Returns: TransactionInfo containing the transaction
        """
        pass

    def install_chaincode(self, cc_install_request, scheduler=None):
        """Install chaincode.

        Args:
            scheduler: see rx.Scheduler
            cc_install_request: see TransactionProposalRequest

        Returns: An rx.Observable of install result

        """
        return chaincode_installment(self).handle(
            cc_install_request, scheduler)

    def instantiate_chaincode(self, cc_instantiate_request, scheduler=None):
        """Instantiate chaincode.

        Args:
            scheduler: see rx.Scheduler
            cc_instantiate_request: see TransactionProposalRequest

        Returns: An rx.Observable of instantiate result

        """
        return chaincode_instantiation(self).handle(
            cc_instantiate_request, scheduler)

    def invoke_chaincode(self, cc_invoke_request, scheduler=None):
        """Invoke chaincode.

        Args:
            cc_invoke_request: see TransactionProposalRequest
            scheduler: see rx.Scheduler

        Returns: An rx.Observable of instantiate result

        """
        return chaincode_invocation(self).handle(
            cc_invoke_request, scheduler)

    def create_transaction(self, proposal_responses):
        """Create a transaction with proposal response.

        Following the endorsement policy.

        Args:
            proposal_responses ([Transaction_Proposal_Response]):
                The array of proposal responses received in the proposal call.


        Returns:
            (Transaction instance): The created transaction object instance.

        """
        return None

    def send_transaction(self, transaction):
        """Send a transaction to the chain's orderer service (one or more
        orderer endpoints) for consensus and committing to the ledger.

        This call is asynchronous and the successful transaction commit is
        notified via a BLOCK or CHAINCODE event. This method must provide a
        mechanism for applications to attach event listeners to handle
        'transaction submitted', 'transaction complete' and 'error' events.

        Args:
            transaction (Transaction): The transaction object constructed above

        Returns:
            result (EventEmitter): an handle to allow the application to
            attach event handlers on 'submitted', 'complete', and 'error'.

        """
        return None

    def generate_tx_id(self, nonce, creator):
        """Generate transaction id by nonce and creator.

        Args:
            nonce: nonce
            creator: a user

        Returns: transaction id

        """
        return self._crypto.hash(nonce + creator.serialize()).hexdigest()
