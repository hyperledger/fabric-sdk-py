from ..constants import DEFAULT_PEER_GRPC_ADDR


class Peer(object):
    """ A peer node in the network.

    It has a specific Grpc channel address.
    """

    def __init__(self, grpc_addr=DEFAULT_PEER_GRPC_ADDR):
        self.grpc_addr = grpc_addr
