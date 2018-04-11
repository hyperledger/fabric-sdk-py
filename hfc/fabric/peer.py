# Copyright 281165273@qq.com. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import logging
import threading

import rx

from hfc.protos.peer import peer_pb2_grpc
from hfc.util.channel import create_grpc_channel

DEFAULT_PEER_ENDPOINT = 'localhost:7051'

_logger = logging.getLogger(__name__ + ".peer")


class Peer(object):
    """ A peer node in the network.

    It has a specific gRPC channel address.
    """

    def __init__(self, name='peer', endpoint=DEFAULT_PEER_ENDPOINT,
                 tls_cacerts=None, opts=None):
        """

        :param endpoint: Endpoint of the peer's gRPC service
        :param tls_cacerts: file path of tls root ca's certificate
        :param opts: optional params
        """
        self._name = name
        self._lock = threading.RLock()
        self._channels = []
        self._endpoint = endpoint
        self._eh_url = None
        self._grpc_options = dict()
        self._ssl_target_name = None
        self._tls_ca_certs_path = None
        self._channel = create_grpc_channel(self._endpoint, tls_cacerts, opts)
        self._endorser_client = peer_pb2_grpc.EndorserStub(self._channel)

    def send_proposal(self, proposal, scheduler=None):
        """ Send an endorsement proposal to endorser

        Args:
            scheduler: rx scheduler
            proposal: The endorsement proposal

        Returns: proposal_response or exception

        """
        _logger.debug("Send proposal={}".format(proposal))
        return rx.Observable.start(
            lambda: self._endorser_client.ProcessProposal(proposal),
            scheduler).map(lambda response: (response, self))

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
            self._ssl_target_name = self._grpc_options[
                'ssl-target-name-override']
            self._channel = create_grpc_channel(
                self._endpoint,
                self._tls_ca_certs_path,
                opts=(('grpc.ssl_target_name_override',
                       self._ssl_target_name),)
            )
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


def create_peer(endpoint=DEFAULT_PEER_ENDPOINT, tls_cacerts=None, opts=None):
    """ Factory method to construct a peer instance

    Args:
        endpoint: endpoint
        tls_cacerts: pem
        opts: opts

    Returns: a peer instance

    """
    return Peer(endpoint=endpoint, tls_cacerts=tls_cacerts, opts=opts)
