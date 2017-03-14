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

from hfc.protos.peer import peer_pb2_grpc
from hfc.util.channel import channel

DEFAULT_PEER_ENDPOINT = 'localhost:7051'

_logger = logging.getLogger(__name__ + ".peer")


class Peer(object):
    """ A peer node in the network.

    It has a specific Grpc channel address.
    """

    def __init__(self, endpoint=DEFAULT_PEER_ENDPOINT, pem=None, opts=None):
        self._endpoint = endpoint
        self._endorser_client = peer_pb2_grpc.EndorserStub(
            channel(self._endpoint, pem, opts))

    def send_proposal(self, proposal, scheduler=None):
        """ Send an endorsement proposal to endorser

        Args:
            proposal: The endorsement proposal

        Returns: proposal_response or exception

        """
        _logger.debug("Send proposal={}".format(proposal))
        return rx.Observable.start(
            lambda: self._endorser_client.ProcessProposal(proposal),
            scheduler).map(lambda response: (response, self))

    @property
    def endpoint(self):
        """Return the endpoint of the peer.

        Returns: endpoint

        """
        return self._endpoint
