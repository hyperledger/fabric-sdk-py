# SPDX-License-Identifier: Apache-2.0

import asyncio
import logging
from asyncio import sleep

from hfc.fabric import Client
from hfc.fabric.peer import create_peer
from test.integration.utils import BaseTestCase
from test.integration.config import E2E_CONFIG

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
test_network = E2E_CONFIG['test-network']
CC_PATH = 'github.com/example_cc'
CC_NAME = 'example_cc'
CC_VERSION = '1.0'


class DiscoveryTest(BaseTestCase):

    def test_discovery(self):
        loop = asyncio.get_event_loop()

        org1 = 'org1.example.com'
        peer_config = test_network['org1.example.com']['peers']['peer0']
        tls_cacerts = peer_config['tls_cacerts']
        opts = (('grpc.ssl_target_name_override',
                 peer_config['server_hostname']),)
        endpoint = peer_config['grpc_request_endpoint']

        peer = create_peer(endpoint=endpoint,
                           tls_cacerts=tls_cacerts,
                           opts=opts)

        # Channel create
        response = loop.run_until_complete(
            self.client.channel_create('orderer.example.com',
                                       self.channel_name,
                                       self.user,
                                       config_yaml=self.config_yaml,
                                       channel_profile=self.channel_profile))
        logger.debug(response)
        self.assertTrue(response)

        # Channel join
        channel = self.client.get_channel(self.channel_name)
        self.assertIsNotNone(channel)

        response = loop.run_until_complete(self.client.channel_join(
            requestor=self.user,
            channel_name=self.channel_name,
            peers=['peer0.' + org1, 'peer1.' + org1],
            orderer='orderer.example.com'
        ))
        self.assertTrue(response)

        # CC install
        responses = loop.run_until_complete(self.client.chaincode_install(
            requestor=self.user,
            peers=['peer0.' + org1, 'peer1.' + org1],
            cc_path=CC_PATH,
            cc_name=CC_NAME,
            cc_version=CC_VERSION
        ))
        self.assertTrue(responses)

        # CC instantiate
        args = ['a', '200', 'b', '300']
        response = loop.run_until_complete(self.client.chaincode_instantiate(
            requestor=self.user,
            channel_name=self.channel_name,
            peers=['peer0.' + org1],
            args=args,
            cc_name=CC_NAME,
            cc_version=CC_VERSION,
            wait_for_event=True
        ))
        logger.debug(response)
        self.assertTrue(response)

        # Query instantiated cc
        responses = loop.run_until_complete(
            self.client.query_instantiated_chaincodes(
                requestor=self.user,
                channel_name=self.channel_name,
                peers=['peer0.' + org1, 'peer1.' + org1]
            ))
        logger.debug(responses)
        self.assertEqual(len(responses), 2)
        '''[chaincodes {
           name: "example_cc"
           version: "1.0"
           path: "github.com/example_cc"
           input: "<nil>"
           escc: "escc"
           vscc: "vscc"
        }
        , chaincodes {
           name: "example_cc"
           version: "1.0"
           path: "github.com/example_cc"
           input: "<nil>"
           escc: "escc"
           vscc: "vscc"
        }
        ]'''

        # sleep 3 seconds for having all peers for discovery
        loop.run_until_complete(sleep(5))

        # TEST: config
        # this one contain 3 queries
        response = loop.run_until_complete(channel._discovery(
            requestor=self.user,
            target=peer,
            config=True,
            interests=[{'chaincodes': [{'name': CC_NAME}]}]
        ))

        self.assertEqual(
            response.results[1].config_result.msps['OrdererMSP'].name,
            'OrdererMSP')
        self.assertEqual(
            list(response.results[0].members.peers_by_org.keys())[0],
            'Org1MSP')
        self.assertEqual(
            response.results[2].cc_query_res.content[0].chaincode, CC_NAME)

        # TEST: query_peer
        results = loop.run_until_complete(
            self.client.query_peers(self.user, peer))
        self.assertEqual(len(results['local_peers']['Org1MSP']['peers']), 2)
        self.assertEqual(results['local_peers']['Org1MSP']['peers']
                         [0]['endpoint'], 'peer0.org1.example.com:7051')
        self.assertEqual(results['local_peers']['Org1MSP']['peers']
                         [1]['endpoint'], 'peer1.org1.example.com:7051')

        # Test init with discovery

        client_discovery = Client()

        loop.run_until_complete(
            client_discovery.init_with_discovery(self.user, peer,
                                                 self.channel_name))

        self.assertEqual(len(client_discovery._orderers), 1)
        self.assertEqual(len(client_discovery._peers), 3)
        self.assertEqual(len(client_discovery._organizations), 3)
