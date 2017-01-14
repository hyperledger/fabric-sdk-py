import logging

import grpc
from google.protobuf import empty_pb2 as google_dot_protobuf_dot_empty__pb2

from ..util.constants import DEFAULT_PEER_GRPC_ADDR
from ..protos.peer import fabric_service_pb2_grpc


class Peer(object):
    """ A peer node in the network.

    It has a specific Grpc channel address.
    """

    def __init__(self, grpc_addr=DEFAULT_PEER_GRPC_ADDR):
        self.grpc_addr = grpc_addr
        self.channel = grpc.insecure_channel(grpc_addr)
        # self.peer_stub = api_pb2.OpenchainStub(self.channel)
        self.endorser_client = fabric_service_pb2_grpc.EndorserStub(
          self.channel)
        self.logger = logging.getLogger(__name__)
        self.logger.info('Init peer with grpc_addr={}'.format(self.grpc_addr))

    def send_proposal(self, proposal):
        """ Send an endorsement proposal to endorser

        Args:
            proposal: The endorsement proposal, see
                      /protos/peer/fabric_proposal.proto
        Return:
            proposal_response
        """
        self.logger.debug("Send proposal={}".format(proposal))
        self.endorser_client.proposeProposal(proposal)
        return None

    # will deprecate
    def peer_list(self):
        """list peer on the chain

            return a list of peer nodes currently connected to the target peer.
            The returned  message structure is defined inside api_pb2.proto
            and fabric_pb2.proto.


            ```
            message PeersMessage {
            repeated PeerEndpoint peers = 1;
            }
            message PeerEndpoint {
            PeerID ID = 1;
            string address = 2;
            enum Type {
            UNDEFINED = 0;
            VALIDATOR = 1;
            NON_VALIDATOR = 2;
            }
            Type type = 3;
            bytes pkiID = 4;
            }
            message PeerID {
            string name = 1;
            }
            ```


            :param:empty
            :return:The peer list on the chain
            """

        peer_response = self.peer_stub.GetPeers(
                google_dot_protobuf_dot_empty__pb2.Empty())
        for peer_message in peer_response.peers:
            self.logger.debug("peer information:"
                              "--IDName:{0}"
                              "--address:{1}"
                              "--type:{2}\n".format(peer_message.ID.name,
                                                    peer_message.address,
                                                    peer_message.type))
        return peer_response
