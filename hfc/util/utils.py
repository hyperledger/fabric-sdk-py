# Copyright IBM Corp. 2016 All Rights Reserved.
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
import base64
import sys
import logging
import random
import os
import tarfile
import io
import time

from google.protobuf.message import DecodeError
from google.protobuf.timestamp_pb2 import Timestamp
from hfc.protos.common import common_pb2, configtx_pb2
from hfc.protos.msp import identities_pb2
from hfc.protos.peer import proposal_pb2, chaincode_pb2
from hfc.protos.utils import create_tx_payload
from hfc.fabric.transaction.tx_proposal_request import CC_INSTALL, \
                                    CC_TYPE_GOLANG, CC_TYPE_NODE

_logger = logging.getLogger(__name__)


def proto_str(x):
    return proto_b(x).decode("utf-8")


proto_b = \
    sys.version_info[0] < 3 and (lambda x: x) or (
        lambda x: x.encode('latin1'))


def create_serialized_identity(user):
    """Create serialized identity from user.

    :param user: The user object that should be serialized.
    :type user: user object
    :return: Protobuf SerializedIdentity of
            the given user object.
    :rtype: serialized_identity
    """
    serialized_identity = identities_pb2.SerializedIdentity()
    serialized_identity.mspid = user.msp_id
    serialized_identity.id_bytes = user.enrollment.cert
    return serialized_identity.SerializeToString()


def build_header(creator, channel_header, nonce):
    """This function will build the common header.

    :param creator: Serialized identity of the creator.
    :type creator: protobuf SerializedIdentity
    :param channel_header: ChannelHeader
    :type channel_header: protobuf ChannelHeader
    :param nonce: Nonce that has been used for the tx_id.
    :type nonce: str
    :return: Returns created protobuf common header.
    :rtype: header
    """
    signature_header = common_pb2.SignatureHeader()
    signature_header.creator = creator
    signature_header.nonce = nonce

    header = common_pb2.Header()
    header.signature_header = signature_header.SerializeToString()
    header.channel_header = channel_header.SerializeToString()

    return header


def build_channel_header(type, tx_id, channel_id,
                         timestamp, epoch=0, extension=None,
                         tls_cert_hash=None):
    """Build channel header.

    :param type: type
    :type type: common_pb2.HeaderType
    :param tx_id: transaction id
    :type tx_id: str
    :param channel_id: channel id
    :type channel_id: str
    :param timestamp: timestamp
    :type timestamp: grpc.timestamp
    :param epoch: epoch (Default value = 0)
    :type epoch: int
    :param extension: extension (Default value = None)
    :param tls_cert_hash:  (Default value = None)
    :return: common_proto.Header instance
    """
    channel_header = common_pb2.ChannelHeader()
    channel_header.type = type
    channel_header.version = 1
    channel_header.channel_id = proto_str(channel_id)
    channel_header.tx_id = proto_str(tx_id)
    channel_header.epoch = epoch
    channel_header.timestamp.CopyFrom(timestamp)

    if tls_cert_hash:
        channel_header.tls_cert_hash = tls_cert_hash

    if extension:
        channel_header.extension = extension
    return channel_header


def string_to_signature(string_signatures):
    """Check if signatures are already in protobuf format.

    :param string_signatures: An list of protobuf ConfigSignatures either
            represented as or serialized as byte strings.
    :type string_signatures: list
    :returns: List of protobuf ConfigSignatures.
    :rtype: list
    """
    signatures = []

    for signature in string_signatures:
        if signature and hasattr(signature, 'header') \
                and hasattr(signature, 'signature'):
            _logger.debug('_string_to_signature - signature is protobuf')
            config_signature = signature

        else:
            _logger.debug('_string_to_signature - signature is string')

            config_signature = configtx_pb2.ConfigSignature()
            config_signature.ParseFromString(signature)

        signatures.append(config_signature)

    return signatures


def current_timestamp():
    """Get current timestamp.

    :return: Current timestamp.
    """
    timestamp = Timestamp()
    timestamp.GetCurrentTime()
    return timestamp


def extract_channel_config(configtx_proto_envelope):
    """Extracts the protobuf 'ConfigUpdate' object out ouf the 'ConfigEnvelope'.

    :param configtx_proto_envelope: The encoded bytes of the
            ConfigEnvelope protofbuf.
    :type configtx_proto_envelope: common_pb2.Envelope
    :return: (config_update) The encoded bytes of the ConfigUpdate protobuf, ready to be signed
    :rtype: configtx_pb2.ConfigUpadeEnvelope.config_update
    :raises ValueError: If there is an error in protobuf_decode due to a wrong or
            not valid profobuf file a ValueError is raised.

    """
    _logger.debug('extract_channel_config - start')

    try:
        envelope = common_pb2.Envelope()
        envelope.ParseFromString(configtx_proto_envelope)

        payload = common_pb2.Payload()
        payload.ParseFromString(envelope.payload)

        configtx = configtx_pb2.ConfigUpdateEnvelope()
        configtx.ParseFromString(payload.data)

    except DecodeError as e:
        _logger.error('extract_channel_config - an error occurred decoding'
                      ' the configtx_proto_envelope: {}'.format(e))
        raise ValueError('The given configtx_proto_envelope was not valid: {}'
                         .format(e))

    return configtx.config_update


def build_cc_proposal(cci_spec, header, transient_map):
    """Create an chaincode transaction proposal

    :param transient_map: transient data map
    :param cci_spec: The spec
    :param header: header of the proposal
    :return: The created proposal
    """
    cc_payload = proposal_pb2.ChaincodeProposalPayload()
    cc_payload.input = cci_spec.SerializeToString()
    if transient_map:
        for name, bytes_value in transient_map.items():
            cc_payload.TransientMap[name] = bytes_value

    proposal = proposal_pb2.Proposal()
    proposal.header = header.SerializeToString()
    proposal.payload = cc_payload.SerializeToString()

    return proposal


def sign_proposal(tx_context, proposal):
    """Sign a proposal

    :param tx_context: transaction context
    :param proposal: proposal to sign on
    :return: Signed proposal
    """
    proposal_bytes = proposal.SerializeToString()
    sig = tx_context.sign(proposal_bytes)

    signed_proposal = proposal_pb2.SignedProposal()
    signed_proposal.signature = sig
    signed_proposal.proposal_bytes = proposal_bytes

    return signed_proposal


def send_transaction_proposal(proposal, tx_context, peers):
    """Send transaction proposal

    :param header: header
    :param tx_context: transaction context
    :param proposal: transaction proposal
    :param peers: peers
    :return: a list containing all the proposal response
    """
    signed_proposal = sign_proposal(tx_context, proposal)

    send_executions = [peer.send_proposal(signed_proposal)
                       for peer in peers]

    return send_executions


def send_transaction(orderers, tran_req, tx_context):
    """Send a transaction to the chain's orderer service (one or more
    orderer endpoints) for consensus and committing to the ledger.

    This call is asynchronous and the successful transaction commit is
    notified via a BLOCK or CHAINCODE event. This method must provide a
    mechanism for applications to attach event listeners to handle
    'transaction submitted', 'transaction complete' and 'error' events.

    :param tx_context: transaction context
    :param orderers: orderers
    :param tran_req: The transaction object
    :type tran_req: TransactionRequest
    :return: (EventEmitter) an handle to allow the application to attach event handlers on 'submitted',
            'complete', and 'error'.
    :rtype: EventEmitter
    """
    if not tran_req:
        _logger.warning("Missing input request object on the transaction "
                        "request")
        raise ValueError(
            "Missing input request object on the transaction request"
        )

    if not tran_req.responses or len(tran_req.responses) < 1:
        _logger.warning("Missing 'proposalResponses' parameter in transaction "
                        "request")
        raise ValueError(
            "Missing 'proposalResponses' parameter in transaction request"
        )

    if not tran_req.proposal:
        _logger.warning("Missing 'proposalResponses' parameter in transaction "
                        "request")
        raise ValueError(
            "Missing 'proposalResponses' parameter in transaction request"
        )

    if len(orderers) < 1:
        _logger.warning("Missing orderer objects on this chain")
        raise ValueError(
            "Missing orderer objects on this chain"
        )

    endorsements = map(lambda res: res.endorsement, tran_req.responses)

    tran_payload_bytes = create_tx_payload(endorsements, tran_req)
    envelope = sign_tran_payload(tx_context, tran_payload_bytes)

    if sys.version_info < (3, 0):
        orderer = random.choice(orderers.values())
    else:
        orderer = random.choice(list(orderers.values()))
    return orderer.broadcast(envelope)


def sign_tran_payload(tx_context, tran_payload_bytes):
    """Sign a transaction payload

    :param signing_identity: id to sign with
    :param tran_payload: transaction payload to sign on
    :param tx_context:
    :param tran_payload_bytes:
    :return: Envelope
    """
    sig = tx_context.sign(tran_payload_bytes)

    envelope = common_pb2.Envelope()
    envelope.signature = sig
    envelope.payload = tran_payload_bytes

    return envelope


def build_tx_req(ProposalResponses):
    """Check the endorsements from peers

    :param reponses: ProposalResponse from endorsers
    :param ProposalResponses:
    :return: an instance of TXRequest
    """

    class TXRequest(object):

        def __init__(self, responses, proposal, header):
            self._responses = responses
            self._proposal = proposal
            self._header = header

        @property
        def responses(self):
            return self._responses

        @property
        def proposal(self):
            return self._proposal

        @property
        def header(self):
            return self._header

    responses, proposal, header = ProposalResponses
    return TXRequest(responses, proposal, header)


def send_install_proposal(tx_context, peers):
    """Send install chaincode proposal

    :param tx_context: transaction context
    :param peers: peers to install chaincode
    :return: a set of proposal response
    """

    if not tx_context:
        raise ValueError("InstallProposalRequest is empty.")

    if not peers:
        raise ValueError("Please specify the peer.")

    cc_deployment_spec = chaincode_pb2.ChaincodeDeploymentSpec()
    cc_deployment_spec.chaincode_spec.type = \
        chaincode_pb2.ChaincodeSpec.Type.Value(
            proto_str(tx_context.tx_prop_req.cc_type))
    cc_deployment_spec.chaincode_spec.chaincode_id.name = \
        proto_str(tx_context.tx_prop_req.cc_name)
    cc_deployment_spec.chaincode_spec.chaincode_id.path = \
        proto_str(tx_context.tx_prop_req.cc_path)
    cc_deployment_spec.chaincode_spec.chaincode_id.version = \
        proto_str(tx_context.tx_prop_req.cc_version)

    if not tx_context.tx_prop_req.packaged_cc:
        cc_deployment_spec.code_package = \
            package_chaincode(
                tx_context.tx_prop_req.cc_path,
                tx_context.tx_prop_req.cc_type)
    else:
        cc_deployment_spec.code_package = \
            tx_context.tx_prop_req.packaged_cc

    channel_header_extension = proposal_pb2.ChaincodeHeaderExtension()
    channel_header_extension.chaincode_id.name = \
        proto_str("lscc")
    channel_header = build_channel_header(
        common_pb2.ENDORSER_TRANSACTION,
        tx_context.tx_id,
        '',
        current_timestamp(),
        tx_context.epoch,
        channel_header_extension.SerializeToString()
    )

    header = build_header(tx_context.identity,
                          channel_header,
                          tx_context.nonce)

    cci_spec = chaincode_pb2.ChaincodeInvocationSpec()
    cci_spec.chaincode_spec.type = \
        chaincode_pb2.ChaincodeSpec.Type.Value(tx_context.tx_prop_req.cc_type)
    cci_spec.chaincode_spec.chaincode_id.name = proto_str("lscc")
    cci_spec.chaincode_spec.input.args.extend(
        [proto_b(CC_INSTALL), cc_deployment_spec.SerializeToString()])
    proposal = build_cc_proposal(
        cci_spec, header,
        tx_context.tx_prop_req.transient_map)
    signed_proposal = sign_proposal(tx_context, proposal)

    responses = [peer.send_proposal(signed_proposal) for peer in peers]
    return responses, proposal, header


# https://jira.hyperledger.org/browse/FAB-7065
# ?page=com.atlassian.jira.plugin.system.issuetabpanels%3Acomment
# -tabpanel&showAll=true
def zeroTarInfo(tarinfo):

    tarinfo.uid = tarinfo.gid = 500
    tarinfo.mode = 100644
    tarinfo.mtime = 0
    tarinfo.pax_headers = {
        'atime': 0,
        'ctime': 0,
    }
    return tarinfo


# http://www.onicos.com/staff/iz/formats/gzip.html
# https://github.com/python/cpython/blob/master/Lib/tarfile.py#L420
class zeroTimeContextManager(object):
    def __enter__(self):
        self.real_time = time.time
        time.time = lambda: 0

    def __exit__(self, type, value, traceback):
        time.time = self.real_time


def _tar_path(proj_path, go_path=None):
    """Tar the project path

    :param proj_path: The full path to the code
    :return: The tar stream.
    """

    if not os.listdir(proj_path):
        raise ValueError("No chaincode file found!")

    tar_stream = io.BytesIO()
    with zeroTimeContextManager():
        dist = tarfile.open(fileobj=tar_stream,
                            mode='w|gz', format=tarfile.GNU_FORMAT)
        for dir_path, _, file_names in os.walk(proj_path):
            for filename in file_names:
                file_path = os.path.join(dir_path, filename)

                with open(file_path, mode='rb') as f:
                    if go_path:
                        arcname = os.path.relpath(file_path, go_path)
                    else:
                        arcname = os.path.relpath(file_path)
                    tarinfo = dist.gettarinfo(file_path, arcname)
                    tarinfo = zeroTarInfo(tarinfo)
                    dist.addfile(tarinfo, f)

        dist.close()
        tar_stream.seek(0)
        return(tar_stream.read())


def package_chaincode(cc_path, cc_type=CC_TYPE_GOLANG):
    """Package all chaincode env into a tar.gz file

    :param cc_path: path to the chaincode
    :param cc_type: chaincode type (Default value = CC_TYPE_GOLANG)
    :return: The chaincode pkg path or None
    """
    _logger.debug('Packaging chaincode path={}, chaincode type={}'.format(
        cc_path, cc_type))

    if not cc_path:
        raise ValueError("Missing chaincode path parameter "
                         "in install proposal request")

    if cc_type == CC_TYPE_GOLANG:
        go_path = os.environ['GOPATH']

        if not go_path:
            raise ValueError("No GOPATH env variable is found")

        proj_path = go_path + '/src/' + cc_path
        _logger.debug('Project path={}'.format(proj_path))

        code_content = _tar_path(proj_path, go_path)
        if code_content:
            return code_content
        else:
            raise ValueError('No chaincode found')

    elif cc_type == CC_TYPE_NODE:

        proj_path = cc_path
        _logger.debug('Project path={}'.format(proj_path))

        code_content = _tar_path(proj_path)
        if code_content:
            return code_content
        else:
            raise ValueError('No chaincode found')

    else:
        raise ValueError(f'Currently only support install {CC_TYPE_GOLANG}, {CC_TYPE_NODE} chaincodes')


def pem_to_der(pem):
    arr = pem.split(b'\n')
    der = b''.join(arr[1:-2])
    return base64.b64decode(der)


# create artificial envelope stream
async def stream_envelope(envelope):
    yield envelope
