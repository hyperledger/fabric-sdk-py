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

from hfc.protos.orderer import ab_pb2_grpc
from hfc.util.channel import create_grpc_channel

DEFAULT_ORDERER_ENDPOINT = 'localhost:7050'

_logger = logging.getLogger(__name__ + ".orderer")


class Orderer(object):
    """ A orderer node in the network.

    It has a specific grpc channel address.
    """

    def __init__(self, endpoint=DEFAULT_ORDERER_ENDPOINT,
                 tls_cacerts=None, opts=None):
        """Creates an orderer object.

        Args:
            endpoint (str): The grpc endpoint of the orderer.
            tls_cacerts (str): The tls certificate for the given
                orderer as bytes.
            opts (tuple): Additional grpc config options as
                tuple e.g. ((key, val),).

        """
        self._endpoint = endpoint
        self._channel = create_grpc_channel(self._endpoint, tls_cacerts, opts)
        self._orderer_client = ab_pb2_grpc.AtomicBroadcastStub(self._channel)

    def broadcast(self, envelope, scheduler=None):
        """Send an broadcast envelope to orderer.

        Args:
            envelope: The message envelope

        Returns: orderer_response or exception

        """
        _logger.debug("Send envelope={}".format(envelope))

        return rx.Observable.start(
            lambda: self._orderer_client.Broadcast(iter([envelope])),
            scheduler).map(self._handle_response_stream)

    def delivery(self, envelope, scheduler=None):
        """ Send an delivery envelop to orderer.

        Args:
            envelope: The message envelope

        Returns: orderer_response or exception

        """
        _logger.debug("Send envelope={}".format(envelope))
        return rx.Observable.start(
            lambda: self._orderer_client.Deliver(iter([envelope])),
            scheduler).map(self._handle_response_stream)

    @property
    def endpoint(self):
        """Return the endpoint of the orderer.

        Returns: endpoint

        """
        return self._endpoint

    def _handle_response_stream(self, responses):
        """Handle response stream.

        Args:
            responses: responses

        Returns: a (response,self) tuple

        """
        for response in responses:
            return response, self
