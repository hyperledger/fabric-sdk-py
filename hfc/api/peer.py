import logging

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

    def send_proposal(self, proposal):
        """ Send an endorsement proposal to endorser

        Args:
            proposal: The endorsement proposal, see
                      /protos/peer/fabric_proposal.proto
        Return:
            proposal_response
        """
        _logger.debug("Send proposal={}".format(proposal))
        self._endorser_client.ProcessProposal(proposal)
        return None
