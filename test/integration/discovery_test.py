# SPDX-License-Identifier: Apache-2.0

import logging
from hfc.fabric.peer import create_peer
from test.integration.utils import get_peer_org_user, \
    BaseTestCase
from test.integration.config import E2E_CONFIG

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logging.basicConfig(level=logging.DEBUG)

test_network = E2E_CONFIG['test-network']


class DiscoveryTest(BaseTestCase):

    def test_query_peer(self):

        # channel = self.client.new_channel(self.channel_name)
        org1 = 'org1.example.com'
        peer_config = test_network['org1.example.com']['peers']['peer0']
        tls_cacerts = peer_config['tls_cacerts']
        opts = (('grpc.ssl_target_name_override',
                 peer_config['server_hostname']),)
        endpoint = peer_config['grpc_request_endpoint']

        peer = create_peer(endpoint=endpoint,
                           tls_cacerts=tls_cacerts,
                           opts=opts)

        org1_admin = get_peer_org_user(org1, 'Admin',
                                       self.client.state_store)

        results = self.client.query_peers(org1_admin, peer)

        self.assertEqual(results['local_peers']['Org1MSP']['peers']
                         [0]['endpoint'], 'peer0.org1.example.com:7051')
