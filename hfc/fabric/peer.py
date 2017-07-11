# Copyright 281165273@qq.com. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import logging
import threading

import rx

from hfc.protos.peer import peer_pb2_grpc
from hfc.util.channel import channel

DEFAULT_PEER_ENDPOINT = 'localhost:7051'

_logger = logging.getLogger(__name__ + ".peer")


class Peer(object):
    """ A peer node in the network.

    It has a specific gRPC channel address.
    """

    def __init__(self, endpoint=DEFAULT_PEER_ENDPOINT, pem=None, opts=None):
        self._lock = threading.RLock()
        self._channels = []
        self._endpoint = endpoint
        self._endorser_client = peer_pb2_grpc.EndorserStub(
            channel(self._endpoint, pem, opts))

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


def create_peer(endpoint=DEFAULT_PEER_ENDPOINT, pem=None, opts=None):
    """ Factory method to construct a peer instance

    Args:
        endpoint: endpoint
        pem: pem
        opts: opts

    Returns: a peer instance

    """
    return Peer(endpoint, pem, opts)
