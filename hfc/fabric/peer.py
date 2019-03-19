# Copyright 281165273@qq.com. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import logging
import threading
from hashlib import sha256

from hfc.protos.discovery import protocol_pb2_grpc
from hfc.protos.common import common_pb2
from hfc.protos.peer import peer_pb2_grpc, events_pb2_grpc
from hfc.protos.utils import create_seek_info, create_seek_payload, \
    create_envelope
from hfc.util.channel import create_grpc_channel
from hfc.util.utils import current_timestamp, \
    build_header, build_channel_header, pem_to_der, stream_envelope

DEFAULT_PEER_ENDPOINT = 'localhost:7051'

_logger = logging.getLogger(__name__ + ".peer")


# TODO should extend Remote base class as in fabric-node-sdk


class Peer(object):
    """ A peer node in the network.

    It has a specific gRPC channel address.
    """

    def __init__(self, name='peer', endpoint=DEFAULT_PEER_ENDPOINT,
                 tls_ca_cert_file=None, client_key_file=None,
                 client_cert_file=None, opts=None):
        """

        :param endpoint: Endpoint of the peer's gRPC service
        :param tls_ca_cert_file: file path of tls root ca's certificate
        :param client_key: file path for Private key used for TLS when making
         client connections
        :param client_cert: file path for X.509 certificate used for TLS when
         making client connections
        :param opts: optional params
        """
        self._name = name
        self._lock = threading.RLock()
        self._channels = []
        self._endpoint = endpoint
        self._grpc_options = dict()
        self._ssl_target_name = None
        self._tls_ca_certs_path = tls_ca_cert_file
        self._client_key_path = client_key_file
        self._client_cert_path = client_cert_file
        self._channel = create_grpc_channel(self._endpoint, tls_ca_cert_file,
                                            client_key_file, client_cert_file,
                                            opts)
        self._endorser_client = peer_pb2_grpc.EndorserStub(self._channel)
        self._discovery_client = protocol_pb2_grpc.DiscoveryStub(self._channel)
        self._event_client = events_pb2_grpc.DeliverStub(self._channel)

    def send_proposal(self, proposal):
        """ Send an endorsement proposal to endorser

        Args:
            proposal: The endorsement proposal

        Returns: ProposalResponse or exception

        """
        _logger.debug("Send proposal={}".format(proposal))
        return self._endorser_client.ProcessProposal(proposal)

    def send_discovery(self, request):
        """Send an request to discovery server

        Args:
            request: a signed request

        Returns:
            QueryResult or exception
        """
        _logger.debug("Send discovery={}".format(request))
        return self._discovery_client.Discover(request)

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
            self._endorser_client = peer_pb2_grpc.EndorserStub(self._channel)
            self._discovery_client = protocol_pb2_grpc.DiscoveryStub(
                self._channel)
            self._event_client = events_pb2_grpc.DeliverStub(self._channel)

        except KeyError as e:
            _logger.error(e)
            return False
        return True

    def get_attrs(self):
        return ",".join("{}={}"
                        .format(k, getattr(self, k))
                        for k in self.__dict__.keys())

    def __str__(self):
        return "[{}:{}]".format(self.__class__.__name__, self.get_attrs())

    @property
    def endpoint(self):
        """Return the endpoint of the peer.

        Returns: endpoint

        """
        return self._endpoint

    @endpoint.setter
    def endpoint(self, endpoint):
        self._endpoint = endpoint

    @property
    def name(self):
        """Get the peer name

        Return: The peer name

        """
        return self._name

    def join(self, chan):
        """ Join a channel

        Args:
            chan: a channel instance

        """
        with self._lock:
            self._channels.append(chan)

    @property
    def channels(self):
        with self._lock:
            return self._channels

    def delivery(self, envelope, scheduler=None, filtered=True):
        """ Send an delivery envelop to event service.

        Args:
            envelope: The message envelope

        Returns: orderer_response or exception

        """
        _logger.debug("Send envelope={}".format(envelope))

        if filtered:
            delivery_result = self._event_client.DeliverFiltered(
                stream_envelope(envelope))
        else:
            delivery_result = self._event_client.Deliver(
                stream_envelope(envelope))
        return delivery_result

    def get_events(self, tx_context, channel_name,
                   start=None, stop=None, filtered=True,
                   behavior='BLOCK_UNTIL_READY'):
        """ get the events of the channel.
        Return: the events in success or None in fail.
        """
        _logger.info("get events")

        seek_info = create_seek_info(start, stop, behavior)

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
        return self.delivery(envelope, filtered=filtered)


def create_peer(endpoint=DEFAULT_PEER_ENDPOINT, tls_cacerts=None,
                client_key=None, client_cert=None, opts=None):
    """ Factory method to construct a peer instance

    Args:
        endpoint: endpoint
        tls_cacerts: pem
        client_key: pem
        client_cert: pem
        opts: opts

    Returns: a peer instance

    """
    return Peer(endpoint=endpoint, tls_ca_cert_file=tls_cacerts,
                client_key_file=client_key, client_cert_file=client_cert,
                opts=opts)
