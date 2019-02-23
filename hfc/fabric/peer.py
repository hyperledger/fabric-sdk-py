# Copyright 281165273@qq.com. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import logging
import threading

from hfc.protos.peer import peer_pb2_grpc
from hfc.util.channel import create_grpc_channel

DEFAULT_PEER_ENDPOINT = 'localhost:7051'

_logger = logging.getLogger(__name__ + ".peer")


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
        self._eh_url = None
        self._grpc_options = dict()
        self._ssl_target_name = None
        self._tls_ca_certs_path = tls_ca_cert_file
        self._client_key_path = client_key_file
        self._client_cert_path = client_cert_file
        self._channel = create_grpc_channel(self._endpoint, tls_ca_cert_file,
                                            client_key_file, client_cert_file,
                                            opts)
        self._endorser_client = peer_pb2_grpc.EndorserStub(self._channel)

    def send_proposal(self, proposal):
        """ Send an endorsement proposal to endorser

        Args:
            proposal: The endorsement proposal

        Returns: ProposalResponse or exception

        """
        _logger.debug("Send proposal={}".format(proposal))
        return self._endorser_client.ProcessProposal(proposal)

    def init_with_bundle(self, info):
        """
        Init the peer with given info dict
        :param info: Dict including all info, e.g., endpoint, grpc option
        :return: True or False
        """
        try:
            self._endpoint = info['url']
            self._eh_url = info['eventUrl']
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
        except KeyError as e:
            print(e)
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
