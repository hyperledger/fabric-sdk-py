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
import gzip
import logging
import os
import tarfile
import tempfile

import rx

from hfc.util.utils import proto_str, proto_b
from .crypto import crypto
from ..protos.common import common_pb2 as common_proto
from ..protos.peer import chaincode_pb2 as chaincode_proto
from ..protos.peer import proposal_pb2

_logger = logging.getLogger(__name__ + ".chain")


class ChaincodeDeploymentRequest(object):
    """Chaincode deployment request object."""

    def __init__(self, chaincode_path, chaincode_name,
                 fcn, chain_id, tx_id,
                 args=None, nonce=crypto.generate_nonce(24),
                 signing_identity=None):
        """Init chaincode deployment request.

        Args:
            chaincode_path: chaincode path
            chaincode_name: chaincode id
            fcn: function name
            args: function args
            chain_id: chain id
            tx_id: tx id
            nonce: nonce
            signing_identity: signing identity
        """
        self._args = [] if args is None else args
        self._chaincode_path = chaincode_path
        self._chaincode_name = chaincode_name
        self._fcn = fcn
        self._chain_id = chain_id
        self._tx_id = tx_id
        self._nonce = nonce
        self._signing_identity = signing_identity

    @property
    def chaincode_path(self):
        """Get chaincode path.

        Returns: chaincode path

        """
        return self._chaincode_path

    @chaincode_path.setter
    def chaincode_path(self, path):
        """Set chaincode path.

        Args: Set chaincode path

        """
        self._chaincode_path = path

    @property
    def chaincode_name(self):
        """Get chaincode id.

        Returns: chaincode name

        """
        return self._chaincode_name

    @chaincode_name.setter
    def chaincode_name(self, chaincode_name):
        """Set chaincode id.

        Args: Set chaincode id

        """
        self._chaincode_name = chaincode_name

    @property
    def fcn(self):
        """Get function name.

        Returns: function name

        """
        return self._fcn

    @fcn.setter
    def fcn(self, fcn):
        """Set function name.

        Args: Set function name

        """
        self._fcn = fcn

    @property
    def args(self):
        """Get args.

        Returns: args

        """
        return self._args

    @args.setter
    def args(self, args):
        """Set args.

        Args: Set args

        """
        self._args = args

    @property
    def chain_id(self):
        """Get chain id.

        Returns: chain id

        """
        return self._chain_id

    @chain_id.setter
    def chain_id(self, chain_id):
        """Set chain id.

        Args: Set chain id

        """
        self._chain_id = chain_id

    @property
    def tx_id(self):
        """Get tx id.

        Returns: tx id

        """
        return self._tx_id

    @tx_id.setter
    def tx_id(self, tx_id):
        """Set tx id.

        Args: Set tx id

        """
        self._tx_id = tx_id

    @property
    def nonce(self):
        """Get nonce.

        Returns: nonce

        """
        return self._nonce

    @nonce.setter
    def nonce(self, nonce):
        """Set nonce.

        Args: Set nonce

        """
        self._nonce = nonce

    @property
    def signing_identity(self):
        """Get signingIdentity.

        Returns: signingIdentity

        """
        return self._signing_identity

    @signing_identity.setter
    def signing_identity(self, signing_identity):
        """Set signingIdentity.

        Args: Set signingIdentity

        """
        self._signing_identity = signing_identity


class Chain(object):
    """ The Chain Object

    The "Chain" object captures settings for a channel, which is created
    by the orderers to isolate transactions delivery to peers participating
    on channel.
    """

    def __init__(self, name, peers=None, orderers=None,
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
        if peer.endpoint not in self._peers:
            self._peers[peer.endpoint] = peer

    def remove_peer(self, endpoint):
        """Remove peer endpoint from a chain object

        Args:
            endpoint(string): grpc address of the peer to remove
        """
        if endpoint in self._peers:
            self._peers.pop(endpoint, None)

    def get_peers(self):
        """Get peers of a chain.

        :return: The peer list on the chain
        """
        return self._peers

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

    def send_deployment_proposal(self, chaincode_deployment_request):
        """Send deployment proposal.

        Args:
            chaincode_deployment_request: see ChaincodeDeploymentRequest

        Returns: An rx.Observable of deployment result

        """
        if len(self._peers) < 1:
            _logger.warning("Missing peer objects "
                            "in Deployment proposal chain")
            return rx.Observable.just(ValueError(
                "Missing peer objects in Deployment proposal chain"))

        if self._is_dev_mode:
            _logger.info("Chaincode deployment is in dev mode")
            return rx.Observable.empty()

        return rx.Observable \
            .just(chaincode_deployment_request) \
            .map(_check_chaincode_deployment_request) \
            .map(lambda req, idx: _create_deployment_proposal(req))

    def create_transaction_proposal(self, chaincode_name, args, sign=True):
        """Create a transaction proposal.

        This involves assembling the proposal with the data (chaincodeID,
        chaincode invocation spec, etc.) and signing it using the private key
        corresponding to the ECert to sign.

        Args:
            chaincode_name (string): The name given to the invoked chaincode
            args (string[]): arguments for the 'invoke' method on the chaincode
            sign (Bool): Whether to sign the transaction, default to True


        Returns:
            (Transaction_Proposal instance): The created Transaction_Proposal
            instance or None.

        """
        return None

    def send_transaction_proposal(self, transaction_proposal, chain, retry=0):
        """Send  the created proposal to peer for endorsement.

        Args:
            transaction_proposal: The transaction proposal data
            chain: The target chain whose peers the proposal will be sent to
            retry: times to retry when failure, by default to 0 (no try)

        Returns:
            (Transaction_Proposal_Response response): The response to send
            proposal request.

        """
        return None

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


def _sign_proposal(signing_identity, proposal):
    """ Sign a proposal
    Args:
        signing_identity: id to sign with
        proposal: proposal to sign on

    Returns: Signed proposal

    """
    proposal_bytes = proposal.SerializeToString()
    sig = signing_identity.sign(proposal_bytes)

    signed_proposal = proposal_pb2.SignedProposal()
    signed_proposal.signature = sig
    signed_proposal.proposal_bytes = proposal_bytes

    return signed_proposal


def _build_proposal(cci_spec, header):
    """ Create an invoke transaction proposal

    Args:
        cci_spec: The spec
        header: header of the proposal

    Returns: The created proposal

    """
    cc_payload = proposal_pb2.ChaincodeProposalPayload()
    cc_payload.input = cci_spec.SerializeToString()

    proposal = proposal_pb2.Proposal()
    proposal.header = header.SerializeToString()
    proposal.payload = cc_payload.SerializeToString()

    return proposal


def _check_chaincode_deployment_request(cc_deployment_req):
    """Check chaincode_deployment_request.

    Args:
        cc_deployment_req: see ChaincodeDeploymentRequest

    Returns: chaincode_deployment_request if no error

    Raises:
            ValueError: Invalid chaincode_deployment_request

    """
    if not cc_deployment_req:
        raise ValueError("Missing input request"
                         " object on the proposal request")

    if not cc_deployment_req.chaincode_name:
        raise ValueError("Missing 'chaincode_name' parameter"
                         " in the proposal request")

    if not cc_deployment_req.chaincode_path:
        raise ValueError("Missing 'chaincode_path' parameter"
                         " in the proposal request")

    if not cc_deployment_req.chain_id:
        raise ValueError("Missing 'chain_id' parameter"
                         " in the proposal request")

    if not cc_deployment_req.tx_id:
        raise ValueError("Missing 'tx_id' parameter"
                         " in the proposal request")

    if not cc_deployment_req.signing_identity:
        raise ValueError("Missing 'signing_identity' parameter"
                         " in the proposal request")

    return cc_deployment_req


def _create_deployment_proposal(cc_deployment_req):
    """Create a chaincode deploy proposal

    This involves assembling the proposal with the data (chaincodeID,
    chaincode invocation spec, etc.) and signing it using the private key
    corresponding to the ECert to sign.

    Args:
        cc_deployment_req: see ChaincodeDeploymentRequest

    Returns: (Proposal): The created Proposal instance or None.

    """
    _logger.debug('Create deployment proposal with '
                  'chaincode_name={},chaincode_path={}'
                  .format(cc_deployment_req.chaincode_name,
                          cc_deployment_req.chaincode_path))

    args_str = [cc_deployment_req.fcn] + cc_deployment_req.args

    cc_deployment_spec = chaincode_proto.ChaincodeDeploymentSpec()
    cc_deployment_spec.chaincode_spec.type = \
        chaincode_proto.ChaincodeSpec.Type.Value('GOLANG')
    cc_deployment_spec.chaincode_spec.chaincode_id.name = \
        proto_str(cc_deployment_req.chaincode_name)
    cc_deployment_spec.chaincode_spec.chaincode_id.path = \
        proto_str(cc_deployment_req.chaincode_path)
    cc_deployment_spec.chaincode_spec.input.args.extend(list(map(
        lambda x: proto_b(x), args_str)))
    cc_deployment_spec.code_package = _package_chaincode(
        cc_deployment_req.chaincode_path)

    header = _build_header(cc_deployment_req.signing_identity,
                           cc_deployment_req.nonce,
                           common_proto.ENDORSER_TRANSACTION,
                           cc_deployment_req.chain_id,
                           cc_deployment_req.tx_id,
                           None,
                           cc_deployment_req.chaincode_name
                           )

    cci_spec = chaincode_proto.ChaincodeInvocationSpec()
    cci_spec.chaincode_spec.type = \
        chaincode_proto.ChaincodeSpec.Type.Value('GOLANG')
    cci_spec.chaincode_spec.chaincode_id.name = proto_str("lccc")
    cci_spec.chaincode_spec.input.args.extend(
        [b'deploy', b'default', cc_deployment_spec.SerializeToString()])
    proposal = _build_proposal(cci_spec, header)

    # TODO: get signing_identity
    # signed_proposal = _sign_proposal(
    #     cc_deployment_req.signing_identity, proposal)
    return proposal


def _package_chaincode(cc_path):
    """ Package all chaincode env into a tar.gz file

    Args:
        cc_path: path to the chaincode

    Returns: The chaincode pkg path or None

    """
    _logger.debug('Packaging chaincode path={}'.format(
        cc_path))

    go_path = os.environ['GOPATH']
    if not cc_path:
        raise ValueError("Missing chaincode path parameter "
                         "in Deployment proposal request")

    if not go_path:
        raise ValueError("No GOPATH env variable is found")

    proj_path = go_path + '/src/' + cc_path
    _logger.debug('Project path={}'.format(proj_path))

    with tempfile.NamedTemporaryFile() as temp:
        with tarfile.open(fileobj=temp, mode='w:gz') as code_writer:
            code_writer.add(proj_path)
        temp.flush()

        with gzip.open(temp.name, 'rb') as code_reader:
            code_content = code_reader.read()

    return code_content


def _build_header(creator, nonce, type, chain_id, tx_id, epoch, cc_name):
    """Build a header for transaction proposal.

    Args:
        creator: user
        nonce: nonce
        type: transaction type
        chain_id: chain id
        tx_id: tx id
        epoch: epoch
        cc_name: chaincode name

    Returns: common_proto.Header instance

    """
    header = common_proto.Header()
    header.signature_header.creator = creator.serialize()
    header.signature_header.nonce = nonce

    header.channel_header.type = type
    header.channel_header.version = 1
    header.channel_header.channel_id = proto_str(chain_id)
    header.channel_header.tx_id = proto_str(tx_id)
    if epoch:
        header.channel_header.epoch = epoch
    if cc_name:
        header_ext = proposal_pb2.ChaincodeHeaderExtension()
        header_ext.chaincode_id.name = proto_str(cc_name)
        header.channel_header.extension = header_ext.SerializeToString()
    return header
