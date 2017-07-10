# Copyright IBM Corp. 2017 All Rights Reserved.
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
import random
import sys
import hashlib

from hfc.fabric.tx_context import TXContext
from hfc.fabric.user import check
from hfc.protos.common import common_pb2
from hfc.protos.orderer import ab_pb2
from hfc.util.utils import proto_str, current_timestamp
from hfc.fabric.channel.installment import chaincode_installment
from hfc.fabric.channel.invocation import chaincode_invocation
from hfc.fabric.channel.instantiation import chaincode_instantiation


class Channel(object):
    """The class represents of the channel. """

    def __init__(self, name, client,
                 orderers=None,
                 peers=None,
                 tcert_batch_size=0,
                 is_dev_mode=False,
                 is_pre_fetch_mode=False):

        self._name = name
        self._client = client
        self._orderers = {} if not orderers else orderers
        self._peers = {} if not peers else peers
        self._tcert_batch_size = tcert_batch_size
        self._is_dev_mode = is_dev_mode
        self._is_pre_fetch_mode = is_pre_fetch_mode

    def add_orderer(self, orderer):
        """Add orderer endpoint to a channel object.

        A channel instance may choose to use a single orderer node, which
        will broadcast requests to the rest of the orderer network. Or if
        the application does not trust the orderer nodes, it can choose to
        use more than one by adding them to the channel instance. And all
        APIs concerning the orderer will broadcast to all orderers
        simultaneously.

        Args:
             orderer: an instance of the Orderer class

        """
        self._orderers[orderer.endpoint] = orderer

    def remove_orderer(self, orderer):
        """Remove orderer endpoint from a channel object.

        Args:
            orderer: an instance of the Orderer class

        """
        if orderer.endpoint in self._orderers:
            self._orderers.pop(orderer.endpoint, None)

    @property
    def orderers(self):
        """Get orderers of a channel.

        Returns: The orderer list on the channel

        """
        return self._orderers

    def _get_tx_context(self, user_context=None):
        """Get tx context

        Args:
            user_context (object): user context

        Returns: A tx_context instance

        Raises: ValueError

        """
        user = user_context if not None else self._client.user_context
        check(user)
        return TXContext(self, user, self._client.crypto_suite)

    def _get_latest_block(self, orderer):
        """ Get latest block from orderer."""
        seek_info = ab_pb2.SeekInfo()
        seek_info.start.newest = ab_pb2.SeekNewest()
        seek_info.stop.newest = ab_pb2.SeekNewest()
        seek_info.behavior = \
            ab_pb2.SeekInfo.SeekBehavior.Value('BLOCK_UNTIL_READY')

        tx_context = self._get_tx_context()
        seek_info_header = self._build_channel_header(
            common_pb2.HeaderType.Value('DELIVER_SEEK_INFO'),
            tx_context.tx_id, self._name, current_timestamp(),
            tx_context.epoch)

        signature_header = common_pb2.SignatureHeader()
        signature_header.creator = tx_context.identity
        signature_header.nonce = tx_context.nonce

        seek_payload = common_pb2.Payload()
        seek_payload.header.signature_header = \
            signature_header.SerializeToString()
        seek_payload.header.channel_header = \
            seek_info_header.SerializeToString()
        seek_payload.data = seek_info.SerializeToString()

        envelope = common_pb2.Envelope()
        envelope.signature = tx_context.sign(seek_payload.SerializeToString())
        envelope.payload = seek_payload.SerializeToString()

    def _get_random_orderer(self):
        if sys.version_info < (3, 0):
            return random.choice(self._orderers.values())
        else:
            return random.choice(list(self._orderers.values()))

    @property
    def is_dev_mode(self):
        """Get is_dev_mode

        Returns: is_dev_mode

        """
        return self._is_dev_mode

    @property
    def name(self):
        """Get channel name.

        Returns: channel name

        """
        return self._name

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
        """Add peer endpoint to a channel object

        :param peer: an instance of the Peer class

        """
        self._peers[peer.endpoint] = peer

    def remove_peer(self, peer):
        """Remove peer endpoint from a channel object

        Args:
            peer: peer

        """
        if peer.endpoint in self._peers:
            self._peers.pop(peer.endpoint, None)

    @property
    def peers(self):
        """Get peers of a channel.

        :return: The peer list on the channel

        """
        return self._peers

    def is_valid_peer(self, peer):
        """Check a peer if it is on this channel

        Returns: True/False

        """
        endpoint = peer.endpoint()
        return endpoint in self._peers

    def state_store(self):
        """Get the key val store instance of the instantiating client.
        Get the KeyValueStore implementation (if any)
        that is currently associated with this channel
        Returns: the current KeyValueStore associated with this
        channel / client.

        """
        return self._client.state_store

    def _build_channel_header(type, tx_id, channel_id,
                              timestamp, epoch=0, extension=None):
        """Build channel.

        Args:
            extension: extension
            timestamp: timestamp
            channel_id: channel id
            tx_id: transaction id
            type: type
            epoch: epoch

        Returns: common_proto.Header instance

        """
        channel_header = common_pb2.ChannelHeader()
        channel_header.type = type
        channel_header.version = 1
        channel_header.channel_id = proto_str(channel_id)
        channel_header.tx_id = proto_str(tx_id)
        channel_header.epoch = epoch
        channel_header.timestamp = timestamp
        if extension:
            channel_header.extension = extension

        return channel_header

    def initialize_channel(self):
        """Initialize a new channel

        Calls the orderer(s) to start building the new channel, which is a
        combination of opening new message stream and connecting the list
        of participating peers.

        :return: True if the channel initialization process was successful,
            False otherwise.

        """
        return True

    def update_channel(self):
        """Update a channel configuration

        Calls the orderer(s) to update an existing channel. This allows the
        addition and deletion of Peer nodes to an existing channel, as well as
        the update of Peer certificate information upon certificate renewals.

        Returns: True if the channel update process was successful,
            False otherwise.

        """
        return True

    def is_readonly(self):
        """Check the channel if read-only

        Get the channel status to see if the underlying channel has been
        terminated, making it a read-only channel, where information
        (transactions and state_store) can be queried but no new transactions
        can be submitted.

        Returns: True if the channel is read-only, False otherwise.

        """
        pass

    def query_info(self):
        """Query the information of channel

        Queries for various useful information on the state of the channel
        (height, known peers).

        Returns: :class:`ChannelInfo` channelinfo with height,
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

    def install_chaincode(self, cc_install_request,
                          signing_identity, scheduler=None):
        """Install chaincode.

        Args:
            signing_identity: signing identity
            scheduler: see rx.Scheduler
            cc_install_request: see TransactionProposalRequest

        Returns: An rx.Observable of install result

        """
        return chaincode_installment(self).handle(
            cc_install_request, signing_identity, scheduler)

    def instantiate_chaincode(self, cc_instantiate_request,
                              signing_identity, scheduler=None):
        """Instantiate chaincode.

        Args:
            signing_identity: signing identity
            scheduler: see rx.Scheduler
            cc_instantiate_request: see TransactionProposalRequest

        Returns: An rx.Observable of instantiate result

        """
        return chaincode_instantiation(self).handle(
            cc_instantiate_request, signing_identity, scheduler)

    def invoke_chaincode(self, cc_invoke_request,
                         signing_identity, scheduler=None):
        """Invoke chaincode.

        Args:
            signing_identity: signing identity
            cc_invoke_request: see TransactionProposalRequest
            scheduler: see rx.Scheduler

        Returns: An rx.Observable of instantiate result

        """
        return chaincode_invocation(self).handle(
            cc_invoke_request, signing_identity, scheduler)

    def generate_tx_id(self, nonce, creator):
        """Generate transaction id by nonce and creator.

        Args:
            nonce: nonce
            creator: a user

        Returns: transaction id

        """
        return hashlib.sha256(nonce + creator.serialize()).hexdigest()
