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
from hashlib import sha256

from hfc.protos.common import common_pb2
from hfc.protos.orderer import ab_pb2_grpc
from hfc.protos.utils import create_seek_info, create_seek_payload, \
    create_envelope
from hfc.util.channel import create_grpc_channel

from hfc.util.utils import current_timestamp, \
    build_header, build_channel_header, stream_envelope, pem_to_der

DEFAULT_ORDERER_ENDPOINT = 'localhost:7050'

_logger = logging.getLogger(__name__ + ".orderer")


class Orderer(object):
    """A orderer node in the network. It has a specific grpc channel address.
    :param object:
    :type object:
    """

    def __init__(self, name='orderer', endpoint=DEFAULT_ORDERER_ENDPOINT,
                 tls_ca_cert_file=None, client_key_file=None,
                 client_cert_file=None, opts=None):
        """Creates an orderer object.

        :param name: defaults to 'orderer'
        :type name: str
        :param endpoint: The grpc endpoint of the orderer, defaults to DEFAULT_ORDERER_ENDPOINT
        :type endpoint: str
        :param tls_ca_cert_file: The tls certificate for the given orderer as bytes, defaults to None
        :type tls_ca_cert_file: str
        :param client_key_file: file path for Private key used for TLS when making client connections,
                                defaults to None
        :type client_key_file: str
        :param client_cert_file: file path for X.509 certificate used for TLS when making client connections,
                                 defaults to None
        :type client_cert_file: str
        :param opts: Additional grpc config options as tuple e.g. ((key, val),), defaults to None
        :type opts: tuple
        """

        self._name = name
        self._endpoint = endpoint
        if opts:
            self._grpc_options = {key: value for (key, value) in opts}
        else:
            self._grpc_options = dict()
        self._ssl_target_name = None
        self._tls_ca_certs_path = tls_ca_cert_file
        self._client_key_path = client_key_file
        self._client_cert_path = client_cert_file
        self._channel = create_grpc_channel(self._endpoint, tls_ca_cert_file,
                                            client_key_file,
                                            client_cert_file, opts)
        self._orderer_client = ab_pb2_grpc.AtomicBroadcastStub(self._channel)

    def init_with_bundle(self, info):
        """Init the peer with given info dict

        :param info: Dict including all info, e.g., endpoint, grpc option
        :return: True/False
        :rtype: Boolean
        """

        try:
            self._endpoint = info['url']
            self._grpc_options = info['grpcOptions']
            self._tls_ca_certs_path = info['tlsCACerts']['path']
            if 'clientKey' in info:
                self._client_key_path = info['clientKey']['path']
            if 'clientCert' in info:
                self._client_cert_path = info['clientCert']['path']
            self._ssl_target_name = self._grpc_options[
                'grpc.ssl_target_name_override']
            self._channel = create_grpc_channel(
                self._endpoint,
                self._tls_ca_certs_path,
                self._client_key_path,
                self._client_cert_path,
                opts=[(opt, value) for opt, value in
                      self._grpc_options.items()])
            self._orderer_client = ab_pb2_grpc.AtomicBroadcastStub(
                self._channel)
        except KeyError as e:
            print(e)
            return False
        return True

    def get_genesis_block(self, tx_context, channel_name):
        """get the genesis block of the channel

        :return: the genesis block in success or None in fail
        :rtype: Block/None
        """
        _logger.info("get genesis block - start")

        seek_info = create_seek_info(0, 0)

        kwargs = {}
        if self._client_cert_path:
            with open(self._client_cert_path, 'rb') as f:
                b64der = pem_to_der(f.read())
                kwargs['tls_cert_hash'] = sha256(b64der).digest()

        seek_info_header = build_channel_header(
            common_pb2.HeaderType.Value('DELIVER_SEEK_INFO'),
            tx_context.tx_id,
            channel_name,
            current_timestamp(),
            tx_context.epoch,
            **kwargs
        )

        seek_header = build_header(
            tx_context.identity,
            seek_info_header,
            tx_context.nonce)

        seek_payload_bytes = create_seek_payload(seek_header, seek_info)
        sig = tx_context.sign(seek_payload_bytes)
        envelope = create_envelope(sig, seek_payload_bytes)

        # this is a stream response
        return self.delivery(envelope)

    def broadcast(self, envelope):
        """Send an broadcast envelope to orderer.

        :param envelope: The message envelope
        :return: orderer_response or exception
        """

        _logger.debug("Send envelope={}".format(envelope))

        # this is a stream response
        return self._orderer_client.Broadcast(stream_envelope(envelope))

    def delivery(self, envelope, scheduler=None):
        """Send an delivery envelop to orderer.

        :param envelope: The message envelope
        :param scheduler: defaults to None
        :return: orderer_response or exception
        """

        _logger.debug("Send envelope={}".format(envelope))

        # this is a stream response
        return self._orderer_client.Deliver(stream_envelope(envelope))

    def get_attrs(self):
        return ",".join("{}={}"
                        .format(k, getattr(self, k))
                        for k in self.__dict__.keys())

    def __str__(self):
        return "[{}:{}]".format(self.__class__.__name__, self.get_attrs())

    @property
    def endpoint(self):
        """Return the endpoint of the orderer.

        :return: endpoint
        """
        return self._endpoint

    @property
    def name(self):
        """Return the name of the orderer.

        :return: name of orderer
        :rtype: str
        """

        return self._name

    def _handle_response_stream(self, responses):
        """Handle response stream.

        :param responses: responses
        :return: response
        :rtype: tuple
        """

        for response in responses:
            return response, self

    def set_tls_client_cert_and_key(self, client_key_file=None,
                                    client_cert_file=None):
        """Set tls client's cert and key for mutual tls

        :param client_key_file: file path for Private key used for TLS when making client connections,
                                defaults to None
        :type client_key_file: str
        :param client_cert_file: file path for X.509 certificate used for TLS when making client connections,
                                 defaults to None
        :type client_cert_file: str
        :return: set success value
        :rtype: Boolean
        """

        try:
            self._client_key_path = client_key_file
            self._client_cert_path = client_cert_file
            self._channel = create_grpc_channel(
                self._endpoint,
                self._tls_ca_certs_path,
                self._client_key_path,
                self._client_cert_path,
                opts=[(opt, value) for opt, value in
                      self._grpc_options.items()])
            self._orderer_client = ab_pb2_grpc.AtomicBroadcastStub(
                self._channel)
        except Exception:
            return False
        return True
