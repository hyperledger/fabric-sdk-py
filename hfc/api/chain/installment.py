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
import io
import logging
import os
import tarfile

import rx

from hfc.api.chain.transactionproposals \
    import TransactionProposalHandler, CC_INSTALL, \
    TransactionProposalRequest, check_tran_prop_request, \
    build_header, build_proposal, sign_proposal, send_transaction_proposal
from hfc.api.crypto import crypto
from hfc.protos.common import common_pb2
from hfc.protos.peer import chaincode_pb2
from hfc.util.utils import proto_str, proto_b, current_timestamp

_logger = logging.getLogger(__name__ + ".installment")

KEEP = ['.go', '.c', '.h']


class Installment(TransactionProposalHandler):
    """Chaincode installment transaction proposal handler. """

    def handle(self, tran_prop_req, scheduler=None):
        """Execute chaincode install transaction proposal request.

        Args:
            scheduler: see rx.Scheduler
            tran_prop_req: chaincode install transaction proposal request

        Returns: An rx.Observer wrapper of chaincode install response

        """
        return _install_chaincode(self._chain, tran_prop_req, scheduler)


def _create_installment_proposal(tran_prop_req, chain):
    """Create a chaincode install proposal

    This involves assembling the proposal with the data (chaincodeID,
    chaincode invocation spec, etc.) and signing it using the private key
    corresponding to the ECert to sign.

    Args:
        tran_prop_req: see TransactionProposalRequest

    Returns: (Proposal): The created Proposal instance or None.

    """

    cc_deployment_spec = chaincode_pb2.ChaincodeDeploymentSpec()
    cc_deployment_spec.chaincode_spec.type = \
        chaincode_pb2.ChaincodeSpec.Type.Value('GOLANG')
    cc_deployment_spec.chaincode_spec.chaincode_id.name = \
        proto_str(tran_prop_req.chaincode_id)
    cc_deployment_spec.chaincode_spec.chaincode_id.path = \
        proto_str(tran_prop_req.chaincode_path)
    cc_deployment_spec.chaincode_spec.chaincode_id.version = \
        proto_str(tran_prop_req.chaincode_version)
    if not chain.is_dev_mode:
        cc_deployment_spec.code_package = _package_chaincode(
            tran_prop_req.chaincode_path) if not \
            tran_prop_req.chaincode_package else \
            tran_prop_req.chaincode_package
    cc_deployment_spec.effective_date.seconds = \
        tran_prop_req.effective_date.seconds
    cc_deployment_spec.effective_date.nanos = \
        tran_prop_req.effective_date.nanos

    header = build_header(tran_prop_req.signing_identity,
                          tran_prop_req.nonce,
                          common_pb2.ENDORSER_TRANSACTION,
                          chain,
                          tran_prop_req.prop_type,
                          chaincode_id="lscc"
                          )

    cci_spec = chaincode_pb2.ChaincodeInvocationSpec()
    cci_spec.chaincode_spec.type = \
        chaincode_pb2.ChaincodeSpec.Type.Value('GOLANG')
    cci_spec.chaincode_spec.chaincode_id.name = proto_str("lscc")
    cci_spec.chaincode_spec.input.args.extend(
        [proto_b(CC_INSTALL), cc_deployment_spec.SerializeToString()])
    proposal = build_proposal(cci_spec, header)

    signed_proposal = sign_proposal(
        tran_prop_req.signing_identity, proposal)
    return signed_proposal


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

    with io.BytesIO() as temp:
        with tarfile.open(fileobj=temp, mode='w|gz') as code_writer:
            for dir_path, _, file_names in os.walk(proj_path):
                for filename in file_names:
                    file_path = os.path.join(dir_path, filename)
                    if _is_source(file_path):
                        code_writer \
                            .add(file_path,
                                 arcname=os.path.relpath(file_path, go_path))
        temp.flush()
        code_content = temp.read()

    return code_content


def _install_chaincode(chain, cc_installment_request, scheduler=None):
    """Install chaincode.

    Args:
        chain: chain instance
        scheduler: see rx.Scheduler
        cc_installment_request: see TransactionProposalRequest

    Returns: An rx.Observable of installment response

    """
    if len(chain.peers) < 1:
        return rx.Observable.just(ValueError(
            "Missing peer objects on this chain"
        ))

    peers = {}
    if cc_installment_request and cc_installment_request.targets:
        peers = cc_installment_request.targets
        for peer in peers:
            if not chain.is_valid_peer(peer):
                return rx.Observable.just(ValueError(
                    'Request targets peer object {} not in chain'.format(peer)
                ))

    if len(peers) < 1:
        peers = chain.peers

    return rx.Observable \
        .just(cc_installment_request) \
        .map(check_tran_prop_request) \
        .map(lambda req, _: _create_installment_proposal(req, chain)) \
        .flat_map(lambda proposal, _:
                  send_transaction_proposal(
                      proposal, peers, scheduler))


def create_installment_proposal_req(chaincode_id, chaincode_path,
                                    chaincode_version, creator,
                                    nonce=crypto.generate_nonce(24),
                                    targets=None,
                                    effective_date=current_timestamp()):
    """Create installment proposal request.

    Args:
        effective_date: effective date
        targets: peers
        nonce: nonce
        chaincode_id: chaincode_id
        chaincode_path: chaincode_path
        chaincode_version: chaincode_version
        creator: user

    Returns: see TransactionProposalRequest

    """
    return TransactionProposalRequest(chaincode_id, creator, CC_INSTALL,
                                      chaincode_path, chaincode_version,
                                      nonce=nonce, targets=targets,
                                      effective_date=effective_date)


def chaincode_installment(chain):
    """Create installment.

    Args:
        chain: chain instance

    Returns: Installment instance

    """
    return Installment(chain)


def _is_source(file_path):
    """Predicate function for determining whether a given path should be
    considered valid source code, based entirely on the extension. It is
    assumed that other checks for file type (e.g. ISREG) have already been
    performed.

    Args:
        file_path: file path

    Returns: true/false

    """
    _, ext = os.path.splitext(file_path)
    return ext in KEEP
