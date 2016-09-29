import grpc
from ..protos import api_pb2
from ..constants import DEFAULT_PEER_GRPC_ADDR
import logging
from google.protobuf import empty_pb2 as google_dot_protobuf_dot_empty__pb2


class Peer(object):
    """ A peer node in the network.

    It has a specific Grpc channel address.
    """

    def __init__(self, grpc_addr=DEFAULT_PEER_GRPC_ADDR):
        self.logger = logging.getLogger(__name__)
        self.channel = grpc.insecure_channel(grpc_addr)
        self.peer_stub = api_pb2.OpenchainStub(self.channel)

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
            self.logger.debug("peer information:--IDName:{0}--address:{1}--type:{2}\n".format(
                   peer_message.ID.name,
                   peer_message.address,
                   peer_message.type))
        return peer_response
