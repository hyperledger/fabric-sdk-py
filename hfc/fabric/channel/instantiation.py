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
import logging

import rx

from hfc.fabric.channel.transactionproposals \
    import TransactionProposalHandler, TransactionProposalRequest, \
    CC_INSTANTIATE, check_tran_prop_request, \
    build_header, build_proposal, sign_proposal
from hfc.protos.common import common_pb2
from hfc.protos.peer import chaincode_pb2
from hfc.util.crypto import crypto
from hfc.util.utils import proto_str, proto_b

# deprecated remain for new code

_logger = logging.getLogger(__name__ + ".instantiate")


class Instantiation(TransactionProposalHandler):
    """Chaincode instantiate transaction proposal handler. """

    def handle(self, tran_prop_req, scheduler=None):
        """Execute chaincode instantiation transaction proposal request.

        Args:
            scheduler: see rx.Scheduler
            tran_prop_req: chaincode instantiation transaction proposal request

        Returns: An rx.Observer wrapper of chaincode instantiation response

        """
        return _instantiate_chaincode(self._chain, tran_prop_req, scheduler)


def _create_instantiation_proposal(tran_prop_req, chain):
    """Create a chaincode instantiation proposal

    This involves assembling the proposal with the data (chaincodeID,
    chaincode invocation spec, etc.) and signing it using the private key
    corresponding to the ECert to sign.

    Args:
        tran_prop_req: see TransactionProposalRequest

    Returns: (Proposal): The created Proposal instance or None.

    """
    args = ["init" if not tran_prop_req.fcn
            else tran_prop_req.fcn] + tran_prop_req.args

    cc_deployment_spec = chaincode_pb2.ChaincodeDeploymentSpec()
    cc_deployment_spec.chaincode_spec.type = \
        chaincode_pb2.ChaincodeSpec.Type.Value('GOLANG')
    cc_deployment_spec.chaincode_spec.chaincode_id.name = \
        proto_str(tran_prop_req.chaincode_id)
    cc_deployment_spec.chaincode_spec.chaincode_id.path = \
        proto_str(tran_prop_req.chaincode_path)
    cc_deployment_spec.chaincode_spec.chaincode_id.version = \
        proto_str(tran_prop_req.chaincode_version)
    cc_deployment_spec.chaincode_spec.input.args.extend(list(map(
        lambda x: proto_b(x), args)))

    header = build_header(tran_prop_req.signing_identity,
                          tran_prop_req.nonce,
                          common_pb2.ENDORSER_TRANSACTION,
                          chain,
                          tran_prop_req.prop_type,
                          chaincode_id=tran_prop_req.chaincode_id
                          )

    cci_spec = chaincode_pb2.ChaincodeInvocationSpec()
    cci_spec.chaincode_spec.type = \
        chaincode_pb2.ChaincodeSpec.Type.Value('GOLANG')
    cci_spec.chaincode_spec.chaincode_id.name = proto_str("lscc")
    cci_spec.chaincode_spec.input.args.extend(
        [proto_b(CC_INSTANTIATE), proto_b('default'),
         cc_deployment_spec.SerializeToString()])
    proposal = build_proposal(cci_spec, header)

    signed_proposal = sign_proposal(
        tran_prop_req.signing_identity, proposal)
    return signed_proposal


def _instantiate_chaincode(chain, cc_instantiation_request, scheduler=None):
    """Instantiate chaincode.

    Args:
        chain: chain instance
        scheduler: see rx.Scheduler
        cc_instantiation_request: see TransactionProposalRequest

    Returns: An rx.Observable of instantiation response

    """
    if len(chain.peers) < 1:
        return rx.Observable.just(ValueError(
            "Missing peer objects on this chain"
        ))

    peers = {}
    if cc_instantiation_request and cc_instantiation_request.targets:
        peers = cc_instantiation_request.targets
        for peer in peers:
            if not chain.is_valid_peer(peer):
                return rx.Observable.just(ValueError(
                    'Request targets peer object {} not in chain'.format(peer)
                ))

    if len(peers) < 1:
        peers = chain.peers

    return rx.Observable \
        .just(cc_instantiation_request) \
        .map(check_tran_prop_request) \
        .map(lambda req, idx: _create_instantiation_proposal(req, chain))
    # .flatmap(lambda proposal, idx:
    #          send_transaction_proposal(proposal, peers, scheduler))


def create_instantiation_proposal_req(chaincode_id, chaincode_path,
                                      chaincode_version, creator,
                                      fcn='init', args=None,
                                      nonce=crypto.generate_nonce(24),
                                      targets=None):
    """Create instantiation proposal request.

    Args:
        fcn: chaincode init function
        args: init function args
        targets: peers
        nonce: nonce
        chaincode_id: chaincode_id
        chaincode_path: chaincode_path
        chaincode_version: chaincode_version
        creator: user

    Returns: see TransactionProposalRequest

    """
    return TransactionProposalRequest(chaincode_id, creator, CC_INSTANTIATE,
                                      chaincode_path, chaincode_version,
                                      fcn=fcn, args=args,
                                      nonce=nonce, targets=targets)


def chaincode_instantiation(chain):
    """Create instantiate.

    Args:
        chain: chain instance

    Returns: Instantiate instance

    """
    return Instantiation(chain)
