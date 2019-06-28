# Copyright 281165273@qq.com. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import logging
import threading

from hfc.protos.discovery import protocol_pb2_grpc
from hfc.protos.peer import peer_pb2_grpc, events_pb2_grpc
from hfc.util.channel import create_grpc_channel
from hfc.util.utils import stream_envelope

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
        if opts:
            self._grpc_options = {key: value for (key, value) in opts}
        else:
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

    def set_tls_client_cert_and_key(self, client_key_file=None,
                                    client_cert_file=None):
        """Set tls client's cert and key for mutual tls

        Args:
            client_key (str): file path for Private key used for TLS when
                making client connections
            client_cert (str): file path for X.509 certificate used for TLS
                when making client connections

        Returns:
            bool: set success value
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
            self._endorser_client = peer_pb2_grpc.EndorserStub(self._channel)
            self._discovery_client = protocol_pb2_grpc.DiscoveryStub(
                self._channel)
            self._event_client = events_pb2_grpc.DeliverStub(self._channel)
        except Exception:
            return False
        return True


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
