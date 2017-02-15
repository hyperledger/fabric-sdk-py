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
import os

import rx

from .crypto import crypto
from ..protos.common import common_pb2 as common_proto
from ..protos.peer import chaincode_pb2 as chaincode_proto
from ..protos.peer import proposal_pb2
from ..util import utils
from ..util.constants import dockerfile_contents


class ChaincodeDeploymentRequest(object):
    """Chaincode deployment request object."""

    def __init__(self, chaincode_path, chaincode_id, fcn, args,
                 chain_id, tx_id,
                 nonce=crypto.generate_nonce(24),
                 signer=None):
        """Init chaincode deployment request.

        Args:
            chaincode_path: chaincode path
            chaincode_id: chaincode id
            fcn: function name
            args: function args
            chain_id: chain id
            tx_id: tx id
            nonce: nonce
            signer: signer

        """
        self._chaincode_path = chaincode_path
        self._chaincode_id = chaincode_id
        self._fcn = fcn
        self._args = args
        self._chain_id = chain_id
        self._tx_id = tx_id
        self._nonce = nonce
        self._signer = signer

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
    def chaincode_id(self):
        """Get chaincode id.

        Returns: chaincode name

        """
        return self._chaincode_id

    @chaincode_id.setter
    def chaincode_id(self, id):
        """Set chaincode id.

        Args: Set chaincode id

        """
        self._chaincode_id = id

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
    def signer(self):
        """Get signer.

        Returns: signer

        """
        return self._signer

    @signer.setter
    def signer(self, signer):
        """Set signer.

        Args: Set signer

        """
        self._signer = signer


class Chain(object):
    """ The Chain Object

    The "Chain" object captures settings for a channel, which is created
    by the orderers to isolate transactions delivery to peers participating
    on channel.
    """

    def __init__(self, name):
        self.name = name
        self.peers = {}
        self.orders = {}
        self.keyValStore = None
        self.tcertBatchSize = 0
        self.logger = logging.getLogger(__name__)
        self.logger.info('Init Chain with name={}'.format(self.name))

    def getKeyValueStore(self):
        """Get the key val store instance

        Get the KeyValueStore implementation (if any)
        that is currently associated with this chain

        :return: the current KeyValueStore associated with this chain,
            or None if not set.
        """
        return self.keyValStore

    def set_kv_store(self, keyValStore):
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
        if peer.endpoint not in self.peers:
            self.peers[peer.endpoint] = peer

    def remove_peer(self, endpoint):
        """Remove peer endpoint from a chain object

        Args:
            endpoint(string): grpc address of the peer to remove
        """
        if endpoint in self.peers:
            self.peers.pop(endpoint, None)

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

        :return: True if the chain is read-only, False otherwise.
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

    def package_chaincode(self, chaincode_path, chaincode_name,
                          dockerfile_contents=dockerfile_contents):
        """ Package all chaincode env into a tar.gz file
        Args:
            chaincode_path: path to the chaincode
            chaincode_name: name of the chaincode
            dockerfile_contents: docker file content

        Returns: The chaincode pkg path or None
        """
        self.logger.debug('Packaging chaincode path={}'.format(chaincode_path))
        go_path = os.environ['GOPATH']
        if not go_path:
            self.logger.warning('No GOPATH env variable is found')
            return None
        proj_path = go_path + '/src/' + chaincode_path
        self.logger.debug('Project path={}'.format(proj_path))
        dockerfile_contents = dockerfile_contents.format(chaincode_name)
        docker_file_path = proj_path + '/Dockerfile'
        try:
            with open(docker_file_path, 'w') as f:
                f.write(dockerfile_contents)
            # TODO: the file should be some tmp file in future
            tz_file_path = '/tmp/deployment-package.tar.gz'
            if not utils.create_targz(proj_path, tz_file_path):
                self.logger.error('Error to create tar.gz file for {}'.format(
                    proj_path))
                return None
        except Exception as e:
            self.logger.error('Exception to package chaincode: {}'.format(e))
            return None
        return tz_file_path

    @staticmethod
    def _build_header(creator, chain_id, chaincode_name, tx_id, nonce):
        """ Build a header for transaction.

            This is a private method.
        Args:
            creator: creator info
            chain_id: id of the chain
            chaincode_name: name of the chaincode
            tx_id: transaction id
            nonce: nonce string

        Returns: the generated header

        """
        channel_header = common_proto.ChannelHeader()
        channel_header.type = common_proto.HeaderType.Value(
            'ENDORSER_TRANSACTION')
        channel_header.tx_id = str(tx_id)
        channel_header.channel_id = chain_id
        if chaincode_name:
            chaincode_id = chaincode_proto.ChaincodeID()
            chaincode_id.name = chaincode_name
            header_ext = proposal_pb2.ChaincodeHeaderExtension()
            header_ext.chaincode_id.name = chaincode_id.name
            channel_header.extension = header_ext.SerializeToString()
        signature_header = common_proto.SignatureHeader()
        signature_header.creator = creator.encode()
        signature_header.nonce = nonce

        header = common_proto.Header()
        header.signature_header.creator = signature_header.creator
        header.signature_header.nonce = signature_header.nonce
        header.channel_header.type = channel_header.type
        header.channel_header.tx_id = channel_header.tx_id
        header.channel_header.channel_id = channel_header.channel_id
        return header

    @staticmethod
    def _build_proposal(invoke_spec, header):
        """ Create an invoke transaction proposal
        Args:
            invoke_spec: The spec
            header: header of the proposal

        Returns: The created proposal

        """
        cci_spec = chaincode_proto.ChaincodeInvocationSpec()
        cci_spec.chaincode_spec.type = invoke_spec['type']
        cci_spec.chaincode_spec.chaincode_id.name = \
            invoke_spec['chaincodeID']['name']
        cci_spec.chaincode_spec.input.args.extend(
            invoke_spec['input']['args'])

        cc_payload = proposal_pb2.ChaincodeProposalPayload()
        cc_payload.input = cci_spec.SerializeToString()

        proposal = proposal_pb2.Proposal()
        proposal.header = header.SerializeToString()
        proposal.payload = cc_payload.SerializeToString()

        return proposal

    @staticmethod
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

    def create_deploy_proposal(self, chaincode_path, chaincode_name, fcn, args,
                               chain_id, tx_id,
                               nonce=crypto.generate_nonce(24),
                               sign=True):
        """Create a chaincode deploy proposal

        This involves assembling the proposal with the data (chaincodeID,
        chaincode invocation spec, etc.) and signing it using the private key
        corresponding to the ECert to sign.

        Args:
            chaincode_path (string): path to the chaincode to deploy
            chaincode_name (string): a custom name to identify the chaincode
                on the chain
            fcn (string): name of the chaincode function to call after deploy
                to initiate the state
            args (string[]): arguments for calling the init function
                designated by 'fcn'
            chain_id (string): id of chain to send, to support multiple chain
            tx_id (string): Transaction id
            nonce (string): Random byte array for avoid repeating attack
            sign (Bool): Whether to sign the transaction, default to True

        Returns: (Proposal): The created Proposal instance or None.

        """
        self.logger.debug('Create deploy proposal with chaincode={}'.format(
            chaincode_name))

        # step 0: construct a chaincode package
        tz_file_path = self.package_chaincode(chaincode_path, chaincode_name)
        if not tz_file_path:
            self.logger.error('Fail to package chaincode')
            return None

        # step 1: construct a chaincode spec
        args_str = [fcn] + args

        # step 2: construct a chaincodedeployment spec
        cc_deployment_spec = chaincode_proto.ChaincodeDeploymentSpec()
        assert not cc_deployment_spec.HasField('chaincode_spec')
        cc_deployment_spec.chaincode_spec.type = \
            chaincode_proto.ChaincodeSpec.Type.Value('GOLANG')

        cc_deployment_spec.chaincode_spec.chaincode_id.name = chaincode_name
        cc_deployment_spec.chaincode_spec.chaincode_id.path = chaincode_path
        cc_deployment_spec.chaincode_spec.input.args.extend(
            list(map(lambda x: x.encode(), args_str)))

        try:
            with open(tz_file_path, 'rb') as f:
                pkg_content = f.read()
                cc_deployment_spec.code_package = pkg_content
        except Exception as e:
            self.logger.error('Failed to read {}'.format(tz_file_path))
            self.logger.error(e)
            return None
        # TODO: add ESCC/VSCC info here
        lccc_spec = {
            'type': chaincode_proto.ChaincodeSpec.Type.Value('GOLANG'),
            'chaincodeID': {
                'name': 'lccc'
            },
            'input': {
                'args': [b'deploy', b'default',
                         cc_deployment_spec.SerializeToString()]
            }
        }

        # step 3: construct a chaincode deploy proposal
        header = self._build_header('admin', chain_id, 'lccc', tx_id, nonce)
        proposal = self._build_proposal(lccc_spec, header)

        # TODO: get signing_identity
        # signed_proposal = self._sign_proposal(signing_identity, proposal)
        # return signed_proposal

        return proposal

    def send_deployment_proposal(self, chaincode_deployment_request):
        """Send deployment proposal.

        Args:
            chaincode_deployment_request: see ChaincodeDeploymentRequest

        Returns: An rx.Observable of deployment result

        """
        if len(self.peers) < 1:
            self.logger.warning('Missing peer objects '
                                'in Deployment proposal chain')

            return rx.Observable.just(ValueError(
                "Missing peer objects in Deployment proposal chain"))

        # TODO:
        # rx.Observable.just(chaincode_deployment_request) \
        #     .filter(_check_chaincode_deployment_request)\
        #     .map()

        return True

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


def _check_chaincode_deployment_request(chaincode_deployment_request):
    """Check chaincode_deployment_request

    Args:
        chaincode_deployment_request: see ChaincodeDeploymentRequest

    Returns: Tuple of (boolean, error message)

    """
    if not chaincode_deployment_request:
        raise ValueError("Missing input request"
                         " object on the proposal request")

    if not chaincode_deployment_request.chaincode_id:
        raise ValueError("Missing 'chaincode_id' parameter"
                         " in the proposal request")

    if not chaincode_deployment_request.chain_id:
        raise ValueError("Missing 'chain_id' parameter"
                         " in the proposal request")

    if not chaincode_deployment_request.tx_id:
        raise ValueError("Missing 'tx_id' parameter in the proposal request")

    if not chaincode_deployment_request.signer:
        raise ValueError("Missing 'signer' parameter in the proposal request")

    return True
