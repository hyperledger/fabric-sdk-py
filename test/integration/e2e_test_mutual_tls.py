# Copyright IBM Corp. 2017 All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
import os
import time

import docker
import logging
import unittest

from hfc.fabric.client import Client
from test.integration.config import E2E_CONFIG
from test.integration.utils import BaseTestCase

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

CC_PATH = 'github.com/example_cc'
CC_NAME = 'example_cc'
CC_VERSION = '1.0'


class E2eTest(BaseTestCase):

    def setUp(self):
        self.gopath_bak = os.environ.get('GOPATH', '')
        gopath = os.path.normpath(os.path.join(os.path.dirname(__file__),
                                               "../fixtures/chaincode"))
        os.environ['GOPATH'] = os.path.abspath(gopath)
        self.channel_tx = \
            E2E_CONFIG['test-network']['channel-artifacts']['channel.tx']
        self.compose_file_path = \
            E2E_CONFIG['test-network']['docker']['compose_file_mutual_tls']

        self.config_yaml = \
            E2E_CONFIG['test-network']['channel-artifacts']['config_yaml']
        self.channel_profile = \
            E2E_CONFIG['test-network']['channel-artifacts']['channel_profile']
        self.client = Client('test/fixtures/network-mutual-tls.json')
        self.channel_name = "businesschannel"  # default application channel
        self.user = self.client.get_user('org1.example.com', 'Admin')
        self.assertIsNotNone(self.user, 'org1 admin should not be None')

        # Boot up the testing network
        self.shutdown_test_env()
        self.start_test_env()
        time.sleep(1)

    def tearDown(self):
        super(E2eTest, self).tearDown()

    def channel_create(self):
        """
        Create an channel for further testing.

        :return:
        """
        logger.info("E2E: Channel creation start: name={}".format(
            self.channel_name))

        # By default, self.user is the admin of org1
        response = self.client.channel_create(
            'orderer.example.com',
            self.channel_name,
            self.user,
            config_yaml=self.config_yaml,
            channel_profile=self.channel_profile)

        self.assertTrue(response)

        logger.info("E2E: Channel creation done: name={}".format(
            self.channel_name))

    def channel_join(self):
        """
        Join peers of two orgs into an existing channels

        :return:
        """

        logger.info("E2E: Channel join start: name={}".format(
            self.channel_name))

        # channel must already exist when to join
        channel = self.client.get_channel(self.channel_name)
        self.assertIsNotNone(channel)

        orgs = ["org1.example.com", "org2.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, 'Admin')
            response = self.client.channel_join(
                requestor=org_admin,
                channel_name=self.channel_name,
                peer_names=['peer0.' + org, 'peer1.' + org],
                orderer_name='orderer.example.com'
            )
            self.assertTrue(response)
            # Verify the ledger exists now in the peer node
            dc = docker.from_env()
            for peer in ['peer0', 'peer1']:
                peer0_container = dc.containers.get(peer + '.' + org)
                code, output = peer0_container.exec_run(
                    'test -f '
                    '/var/hyperledger/production/ledgersData/chains/chains/{}'
                    '/blockfile_000000'.format(self.channel_name))
                self.assertEqual(code, 0, "Local ledger not exists")

        logger.info("E2E: Channel join done: name={}".format(
            self.channel_name))

    def chaincode_install(self):
        """
        Test installing an example chaincode to peer

        :return:
        """
        logger.info("E2E: Chaincode install start")

        orgs = ["org1.example.com", "org2.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            response = self.client.chaincode_install(
                requestor=org_admin,
                peer_names=['peer0.' + org, 'peer1.' + org],
                cc_path=CC_PATH,
                cc_name=CC_NAME,
                cc_version=CC_VERSION
            )
            self.assertTrue(response)
            # Verify the cc pack exists now in the peer node
            dc = docker.from_env()
            for peer in ['peer0', 'peer1']:
                peer0_container = dc.containers.get(peer + '.' + org)
                code, output = peer0_container.exec_run(
                    'test -f '
                    '/var/hyperledger/production/chaincodes/example_cc.1.0')
                self.assertEqual(code, 0, "chaincodes pack not exists")

        logger.info("E2E: chaincode install done")

    def chaincode_install_fail(self):

        pass

    def chaincode_instantiate(self):
        """
        Test instantiating an example chaincode to peer

        :return:
        """
        logger.info("E2E: Chaincode instantiation start")

        orgs = ["org1.example.com"]
        args = ['a', '200', 'b', '300']
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            response = self.client.chaincode_instantiate(
                requestor=org_admin,
                channel_name=self.channel_name,
                peer_names=['peer0.' + org],
                args=args,
                cc_name=CC_NAME,
                cc_version=CC_VERSION
            )
            logger.info(
                "E2E: Chaincode instantiation response {}".format(response))
            self.assertTrue(response)
        logger.info("E2E: chaincode instantiation done")

    def chaincode_invoke(self):
        """
        Test invoking an example chaincode to peer

        :return:
        """
        logger.info("E2E: Chaincode invoke start")

        orgs = ["org1.example.com"]
        args = ['a', 'b', '100']
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            response = self.client.chaincode_invoke(
                requestor=org_admin,
                channel_name=self.channel_name,
                peer_names=['peer1.' + org],
                args=args,
                cc_name=CC_NAME,
                cc_version=CC_VERSION,
                wait_for_event=True
            )
            self.assertEqual(response, '')

        logger.info("E2E: chaincode invoke done")

    def chaincode_query(self):
        """
        Test invoking an example chaincode to peer

        :return:
        """
        logger.info("E2E: Chaincode query start")

        orgs = ["org1.example.com"]
        args = ['b']
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            response = self.client.chaincode_query(
                requestor=org_admin,
                channel_name=self.channel_name,
                peer_names=['peer0.' + org],
                args=args,
                cc_name=CC_NAME,
                cc_version=CC_VERSION
            )
            self.assertEqual(response, '400')  # 300 + 100

        logger.info("E2E: chaincode query done")

    def query_installed_chaincodes(self):
        """
        Test query installed chaincodes on peer

        :return:
        """
        logger.info("E2E: Query installed chaincode start")

        orgs = ["org1.example.com", "org2.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            response = self.client.query_installed_chaincodes(
                requestor=org_admin,
                peer_names=['peer0.' + org, 'peer1.' + org],
            )
            self.assertEqual(
                response.chaincodes[0].name, CC_NAME, "Query failed")
            self.assertEqual(
                response.chaincodes[0].version, CC_VERSION, "Query failed")
            self.assertEqual(
                response.chaincodes[0].path, CC_PATH, "Query failed")

        logger.info("E2E: Query installed chaincode done")

    def query_channels(self):
        """
        Test querying channel

        :return:
        """
        logger.info("E2E: Query channel start")

        orgs = ["org1.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            response = self.client.query_channels(
                requestor=org_admin,
                peer_names=['peer0.' + org, 'peer1.' + org],
            )
            self.assertEqual(
                response.channels[0].channel_id,
                'businesschannel',
                "Query failed")

        logger.info("E2E: Query channel done")

    def query_info(self):
        """
        Test querying information on the state of the Channel

        :return:
        """
        logger.info("E2E: Query info start")

        orgs = ["org1.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            response = self.client.query_info(
                requestor=org_admin,
                channel_name=self.channel_name,
                peer_names=['peer0.' + org, 'peer1.' + org],
            )
            self.assertEqual(
                response.height,
                3,
                "Query failed")

        logger.info("E2E: Query info done")

    def query_block_by_txid(self):
        """
        Test querying block by tx id

        :return:
        """
        logger.info("E2E: Query block by tx id start")

        orgs = ["org1.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")

            response = self.client.query_info(
                requestor=org_admin,
                channel_name=self.channel_name,
                peer_names=['peer0.' + org, 'peer1.' + org],
            )

            response = self.client.query_block_by_hash(
                requestor=org_admin,
                channel_name=self.channel_name,
                peer_names=['peer0.' + org, 'peer1.' + org],
                block_hash=response.currentBlockHash
            )

            tx_id = response.get('data').get('data')[0].get(
                'payload').get('header').get(
                'channel_header').get('tx_id')

            response = self.client.query_block_by_txid(
                requestor=org_admin,
                channel_name=self.channel_name,
                peer_names=['peer0.' + org, 'peer1.' + org],
                tx_id=tx_id
            )

            self.assertEqual(
                response.get('data').get('data')[0].get(
                    'payload').get('header').get(
                    'channel_header').get('tx_id'),
                tx_id,
                "Query failed")

        logger.info("E2E: Query block by tx id done")

    def query_block_by_hash(self):
        """
        Test querying block by block hash

        :return:
        """
        logger.info("E2E: Query block by block hash start")

        orgs = ["org1.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")

            response = self.client.query_info(
                requestor=org_admin,
                channel_name=self.channel_name,
                peer_names=['peer0.' + org, 'peer1.' + org],
            )

            previous_block_hash = response.previousBlockHash
            current_block_hash = response.currentBlockHash
            response = self.client.query_block_by_hash(
                requestor=org_admin,
                channel_name=self.channel_name,
                peer_names=['peer0.' + org, 'peer1.' + org],
                block_hash=current_block_hash
            )

            self.assertEqual(
                response['header']['previous_hash'].decode('utf-8'),
                previous_block_hash.hex(),
                "Query failed")

        logger.info("E2E: Query block by block hash done")

    def query_block(self):
        """
        Test querying block by block number

        :return:
        """
        logger.info("E2E: Query block by block number start")

        orgs = ["org1.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            response = self.client.query_block(
                requestor=org_admin,
                channel_name=self.channel_name,
                peer_names=['peer0.' + org, 'peer1.' + org],
                block_number='0'
            )
            self.assertEqual(
                response['header']['number'],
                0,
                "Query failed")
            self.blockheader = response['header']

        logger.info("E2E: Query block by block number done")

    def query_transaction(self):
        """
        Test querying transaction by tx id

        :return:
        """
        logger.info("E2E: Query transaction by tx id start")
        orgs = ["org1.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")

            response = self.client.query_info(
                requestor=org_admin,
                channel_name=self.channel_name,
                peer_names=['peer0.' + org, 'peer1.' + org],
            )

            response = self.client.query_block_by_hash(
                requestor=org_admin,
                channel_name=self.channel_name,
                peer_names=['peer0.' + org, 'peer1.' + org],
                block_hash=response.currentBlockHash
            )

            tx_id = response.get('data').get('data')[0].get(
                'payload').get('header').get(
                'channel_header').get('tx_id')

            response = self.client.query_transaction(
                requestor=org_admin,
                channel_name=self.channel_name,
                peer_names=['peer0.' + org, 'peer1.' + org],
                tx_id=tx_id
            )

            self.assertEqual(
                response.get('transaction_envelope').get('payload').get(
                    'header').get('channel_header').get('channel_id'),
                self.channel_name,
                "Query failed")

        logger.info("E2E: Query transaction by tx id done")

    def query_instantiated_chaincodes(self):
        """
        Test query instantiated chaincodes on peer

        :return:
        """
        logger.info("E2E: Query installed chaincode start")

        orgs = ["org1.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            response = self.client.query_instantiated_chaincodes(
                requestor=org_admin,
                channel_name=self.channel_name,
                peer_names=['peer0.' + org, 'peer1.' + org]
            )
            self.assertEqual(
                response.chaincodes[0].name, CC_NAME, "Query failed")
            self.assertEqual(
                response.chaincodes[0].version, CC_VERSION, "Query failed")
            self.assertEqual(
                response.chaincodes[0].path, CC_PATH, "Query failed")

        logger.info("E2E: Query installed chaincode done")

    def get_channel_config(self):
        """
        Test get channel config on peer

        :return:
        """
        logger.info("E2E: Get channel config start")

        orgs = ["org1.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            response = self.client.get_channel_config(
                requestor=org_admin,
                channel_name=self.channel_name,
                peer_names=['peer0.' + org, 'peer1.' + org]
            )
            self.assertEqual(response.config.sequence,
                             1, "Get Config Failed")

        logger.info("E2E: Query installed chaincode done")

    def get_events(self):

        org = 'org1.example.com'
        peer = self.client.get_peer('peer0.' + org)

        org_admin = self.client.get_user(org, 'Admin')
        events = self.client.get_events(org_admin, peer, self.channel_name,
                                        filtered=True,
                                        behavior='FAIL_IF_NOT_READY')

        self.assertEqual(len(events), 4)

        self.assertEqual(events[0]['number'], 0)
        self.assertEqual(events[0]['channel_id'], self.channel_name)

        filtered_transaction = events[0]['filtered_transactions'][0]
        self.assertEqual(filtered_transaction['tx_validation_code'], 'VALID')
        self.assertEqual(filtered_transaction['txid'], '')
        self.assertEqual(filtered_transaction['type'], 'CONFIG')

        self.assertEqual(events[2]['number'], 2)
        filtered_transaction = events[2]['filtered_transactions'][0]
        self.assertEqual(filtered_transaction['tx_validation_code'], 'VALID')
        self.assertEqual(filtered_transaction['type'], 'ENDORSER_TRANSACTION')

        # test missing block is present
        data = {'channel_id': '', 'filtered_transactions': [], 'number': 0}
        self.assertEqual(events[len(events) - 1], data)

    def test_in_sequence(self):

        logger.info("\n\nE2E testing started...")

        self.channel_create()

        self.channel_join()

        self.chaincode_install()

        self.chaincode_install_fail()

        self.chaincode_instantiate()

        self.chaincode_invoke()

        self.chaincode_query()

        self.query_instantiated_chaincodes()

        self.query_installed_chaincodes()

        self.query_channels()

        self.query_info()

        self.query_block_by_txid()

        self.query_block_by_hash()

        self.query_block()

        self.query_transaction()

        self.get_channel_config()

        self.get_events()

        logger.info("E2E all test cases done\n\n")


if __name__ == "__main__":
    unittest.main()
