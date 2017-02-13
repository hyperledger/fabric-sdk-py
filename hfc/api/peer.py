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
        self.endpoint = endpoint
        self._endorser_client = peer_pb2_grpc.EndorserStub(
            channel(self.endpoint, pem, opts))
        _logger.info('Init peer with endpoint={}'.format(self.endpoint))

    def send_proposal(self, proposal, scheduler=None):
        """ Send an endorsement proposal to endorser

        Args:
            proposal: The endorsement proposal
            scheduler: Scheduler, see rx.concurrency

        Returns: An rx.Observable of proposal_response or exception

        """
        _logger.debug("Send proposal={}".format(proposal))
        return rx.Observable.start(
            self._endorser_client.ProcessProposal(proposal), scheduler)
