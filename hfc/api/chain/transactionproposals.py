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
from abc import ABCMeta, abstractmethod

import rx
import six

from hfc.api.crypto import crypto
from hfc.protos.common import common_pb2
from hfc.protos.peer import proposal_pb2
from hfc.util.utils import current_timestamp, proto_str

CC_INSTALL = "install"
CC_INSTANTIATE = "deploy"
CC_INVOKE = "invoke"


@six.add_metaclass(ABCMeta)
class TransactionProposalHandler(object):
    """ An abstract base class for transaction proposal handler.

    Transaction proposal request of different type will be delegated to
    different implementation.
    """

    def __init__(self, chain):
        """Create TransactionProposalHandler instance with chain

        Args:
            chain: chain instance
        """
        self._chain = chain

    @abstractmethod
    def handle(self, tran_prop_req, scheduler=None):
        """Handle the transaction proposal request and return the result

        Args:
            scheduler: see rx.Scheduler
            tran_prop_req: transaction proposal request

        Returns: An rx.Observer wrapper of result

        """


class TransactionProposalRequest(object):
    """Transaction proposal request object."""

    def __init__(self, chaincode_id,
                 signing_identity,
                 prop_type,
                 chaincode_path=None,
                 chaincode_version=None,
                 chaincode_package=None,
                 fcn=None,
                 args=None,
                 bytes_args=None,
                 nonce=crypto.generate_nonce(24),
                 targets=None,
                 effective_date=current_timestamp()):
        """Init transaction proposal request.

        Args:
            chaincode_package: chaincode package bytes
            effective_date: effective date
            chaincode_path: chaincode path
            chaincode_id: chaincode id
            chaincode_version: chaincode version
            fcn: function name
            args: function args
            nonce: nonce
            signing_identity: signing identity
            targets: peers to send
            prop_type: transaction type
        """
        self._args = [] if args is None else args
        self._chaincode_path = chaincode_path
        self._chaincode_id = chaincode_id
        self._chaincode_version = chaincode_version
        self._fcn = fcn
        self._nonce = nonce
        self._signing_identity = signing_identity
        self._targets = {} if targets is None else targets
        self._prop_type = prop_type
        self._effective_date = effective_date
        self._chaincode_package = chaincode_package
        self._bytes_args = bytes_args

    @property
    def bytes_args(self):
        """Get bytes args.

        Returns: bytes args

        """
        return self._bytes_args

    @bytes_args.setter
    def bytes_args(self, bytes_args):
        """Set bytes args.

        Args: Set bytes args

        """
        self._bytes_args = bytes_args

    @property
    def chaincode_package(self):
        """Get chaincode package.

        Returns: chaincode package

        """
        return self._chaincode_package

    @chaincode_package.setter
    def chaincode_package(self, chaincode_package):
        """Set chaincode package.

        Args: Set chaincode package

        """
        self._chaincode_package = chaincode_package

    @property
    def effective_date(self):
        """Get effective date.

        Returns: effective date

        """
        return self._effective_date

    @effective_date.setter
    def effective_date(self, effective_date):
        """Set effective date.

        Args: Set effective date

        """
        self._effective_date = effective_date

    @property
    def prop_type(self):
        """Get transaction type.

        Returns: transaction type

        """
        return self._prop_type

    @prop_type.setter
    def prop_type(self, prop_type):
        """Set transaction type.

        Args: Set transaction type

        """
        self._prop_type = prop_type

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

        Returns: chaincode id

        """
        return self._chaincode_id

    @chaincode_id.setter
    def chaincode_id(self, chaincode_id):
        """Set chaincode id.

        Args: Set chaincode id

        """
        self._chaincode_id = chaincode_id

    @property
    def chaincode_version(self):
        """Get chaincode version.

        Returns: chaincode version

        """
        return self._chaincode_version

    @chaincode_version.setter
    def chaincode_version(self, chaincode_version):
        """Set chaincode version.

        Args: Set chaincode version

        """
        self._chaincode_version = chaincode_version

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

    def add_args(self, args):
        """Set args.

        Args: Set args

        """
        self._args += args

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

    @property
    def targets(self):
        """Get targets.

        Returns: targets

        """
        return self._targets

    def add_target(self, target):
        """Add a target.

        Args: a peer

        """
        self._targets[target.endpoint] = target


def check_tran_prop_request(tran_prop_req):
    """Check transaction proposal request.

    Args:
        tran_prop_req: see TransactionProposalRequest

    Returns: transaction proposal request if no error

    Raises:
            ValueError: Invalid transaction proposal request

    """
    if not tran_prop_req:
        raise ValueError("Missing input request"
                         "object on the proposal request ")

    if not tran_prop_req.chaincode_id:
        raise ValueError("Missing 'chaincode_id' parameter "
                         "in the proposal request")

    if tran_prop_req.prop_type == CC_INSTANTIATE \
            or tran_prop_req.prop_type == CC_INSTALL:
        if not tran_prop_req.chaincode_path:
            raise ValueError("Missing 'chaincode_path' parameter "
                             "in the proposal request")

    if not tran_prop_req.chaincode_version:
        raise ValueError("Missing 'chaincode_version' parameter "
                         "in the proposal request")

    if not tran_prop_req.signing_identity:
        raise ValueError("Missing 'signing_identity' parameter "
                         "in the proposal request")

    if tran_prop_req.prop_type != CC_INSTALL:
        if not tran_prop_req.fcn:
            raise ValueError("Missing 'fcn' parameter "
                             "in the proposal request")

    if tran_prop_req.prop_type == CC_INVOKE:
        if not tran_prop_req.args:
            raise ValueError("Missing 'args' parameter "
                             "in the proposal request")
    return tran_prop_req


def build_header(creator, nonce, tran_prop_type,
                 chain, prop_type, epoch=0, chaincode_id=None):
    """Build a header for transaction proposal.

    Args:
        prop_type: prop type
        creator: user
        nonce: nonce
        tran_prop_type: transaction proposal type
        chain: chain instance
        epoch: epoch
        chaincode_id: chaincode id

    Returns: common_proto.Header instance

    """
    header = common_pb2.Header()

    signature_header = common_pb2.SignatureHeader()
    signature_header.creator = creator.serialize()
    signature_header.nonce = nonce
    header.signature_header = signature_header.SerializeToString()

    channel_header = common_pb2.ChannelHeader()
    channel_header.type = tran_prop_type
    channel_header.version = 1
    if prop_type != CC_INSTALL:
        channel_header.channel_id = proto_str(chain.name)
    channel_header.tx_id = proto_str(
        chain.generate_tx_id(nonce, creator))
    channel_header.epoch = epoch
    if chaincode_id:
        header_ext = proposal_pb2.ChaincodeHeaderExtension()
        header_ext.chaincode_id.name = proto_str(chaincode_id)
        channel_header.extension = header_ext.SerializeToString()
    header.channel_header = channel_header.SerializeToString()

    return header


def build_proposal(cci_spec, header):
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


def sign_proposal(signing_identity, proposal):
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


def send_transaction_proposal(proposal, peers, scheduler=None):
    """Send transaction proposal

    Args:
        proposal: transaction proposal
        peers: peers
        scheduler: see rx.Scheduler

    Returns: a rx.Observer wrapper of response

    """
    send_executions = [peer.send_proposal(proposal, scheduler)
                       for peer in peers.values()]

    return rx.Observable.merge(send_executions)
