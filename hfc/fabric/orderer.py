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
import sys

from hfc.protos.common import common_pb2
from hfc.protos.orderer import ab_pb2_grpc
from hfc.protos.utils import create_seek_info, create_seek_payload, \
    create_envelope
from hfc.util.channel import create_grpc_channel

from hfc.util.utils import current_timestamp, \
    build_header, build_channel_header

if sys.version_info < (3, 0):
    from Queue import Queue
else:
    from queue import Queue

DEFAULT_ORDERER_ENDPOINT = 'localhost:7050'

_logger = logging.getLogger(__name__ + ".orderer")


class Orderer(object):
    """ A orderer node in the network.

    It has a specific grpc channel address.
    """

    def __init__(self, name='orderer', endpoint=DEFAULT_ORDERER_ENDPOINT,
                 tls_ca_cert_file=None, opts=None):
        """Creates an orderer object.

        Args:
            endpoint (str): The grpc endpoint of the orderer.
            tls_ca_cert_file (str): The tls certificate for the given
                orderer as bytes.
            opts (tuple): Additional grpc config options as
                tuple e.g. ((key, val),).

        """
        self._name = name
        self._endpoint = endpoint
        self._grpc_options = dict()
        self._ssl_target_name = None
        self._tls_ca_certs_path = tls_ca_cert_file
        self._channel = create_grpc_channel(self._endpoint, tls_ca_cert_file,
                                            opts)
        self._orderer_client = ab_pb2_grpc.AtomicBroadcastStub(self._channel)

    def init_with_bundle(self, info):
        """
        Init the peer with given info dict
        :param info: Dict including all info, e.g., endpoint, grpc option
        :return: True or False
        """
        try:
            self._endpoint = info['url']
            self._grpc_options = info['grpcOptions']
            self._tls_ca_certs_path = info['tlsCACerts']['path']
            self._ssl_target_name = self._grpc_options[
                'ssl-target-name-override']
            self._channel = create_grpc_channel(
                self._endpoint, self._tls_ca_certs_path,
                opts=(('grpc.ssl_target_name_override',
                       self._ssl_target_name),))
            self._orderer_client = ab_pb2_grpc.AtomicBroadcastStub(
                self._channel)
        except KeyError as e:
            print(e)
            return False
        return True

    def get_genesis_block(self, tx_context, channel_name):
        """ get the genesis block of the channel.
        Return: the genesis block in success or None in fail.
        """
        _logger.info("get genesis block - start")

        seek_info = create_seek_info(0, 0)
        seek_info_header = build_channel_header(
            common_pb2.HeaderType.Value('DELIVER_SEEK_INFO'),
            tx_context.tx_id,
            channel_name,
            current_timestamp(),
            tx_context.epoch)

        seek_header = build_header(
            tx_context.identity,
            seek_info_header,
            tx_context.nonce)

        seek_payload_bytes = create_seek_payload(seek_header, seek_info)
        sig = tx_context.sign(seek_payload_bytes)

        envelope = create_envelope(sig, seek_payload_bytes)
        q = Queue(1)
        response = self.delivery(envelope)
        response.subscribe(on_next=lambda x: q.put(x),
                           on_error=lambda x: q.put(x))

        res, _ = q.get(timeout=5)

        if res.block is None or res.block == '':
            _logger.error("fail to get genesis block")
            return None

        _logger.info("get genesis block successfully, block=%s",
                     res.block.header)
        return res.block

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

    def get_attrs(self):
        return ",".join("{}={}"
                        .format(k, getattr(self, k))
                        for k in self.__dict__.keys())

    def __str__(self):
        return "[{}:{}]".format(self.__class__.__name__, self.get_attrs())

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
