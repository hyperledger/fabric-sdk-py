"""
# Copyright IBM Corp. 2017 All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
"""


import docker
import logging
import time
import unittest

from test.integration.utils import BaseTestCase
from test.integration.config import E2E_CONFIG

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
test_network = E2E_CONFIG['test-network']

CC_PATH = 'github.com/example_cc'
CC_NAME = 'example_cc'
CC_VERSION = 'v1'


class E2eTest(BaseTestCase):

    def setUp(self):
        super(E2eTest, self).setUp()

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
        response = self.client.channel_create('orderer.example.com',
                                              self.channel_name,
                                              self.user,
                                              self.channel_tx)
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
                requester=org_admin,
                channel_name=self.channel_name,
                peer_names=['peer0.'+org, 'peer1.'+org],
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
                peer_names=['peer0.'+org, 'peer1.'+org],
                cc_path=CC_PATH,
                cc_name=CC_NAME,
                cc_version=CC_VERSION
            )
            self.assertTrue(response)
            # Verify the cc pack exists now in the peer node
            dc = docker.from_env()
            for peer in ['peer0', 'peer1']:
                peer0_container = dc.containers.get(peer+'.'+org)
                code, output = peer0_container.exec_run(
                    'test -f '
                    '/var/hyperledger/production/chaincodes/example_cc.v1')
                self.assertEqual(code, 0, "chaincodes pack not exists")

        logger.info("E2E: chaincode install done")

    def chaincode_install_fail(self):

        pass

    def instantiate_chaincode(self):

        pass

    def invoke_transaction(self):

        pass

    def query(self):

        pass

    def test_in_sequence(self):

        logger.info("\n\nE2E testing started...")

        self.channel_create()
        time.sleep(5)  # wait for channel created

        self.channel_join()

        self.chaincode_install()

        self.chaincode_install_fail()

        self.instantiate_chaincode()

        self.invoke_transaction()

        self.query()

        logger.info("E2E all test cases done\n\n")


if __name__ == "__main__":
    unittest.main()
