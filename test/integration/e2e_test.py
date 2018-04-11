"""
# Copyright IBM Corp. 2017 All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
"""


import unittest
import logging
import time

from test.integration.utils import BaseTestCase
from test.integration.config import E2E_CONFIG

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
test_network = E2E_CONFIG['test-network']


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
        # wait for channel created
        time.sleep(5)

        logger.info("E2E: Channel join start: name={}".format(
            self.channel_name))

        # channel must already exist when to join
        channel = self.client.get_channel(self.channel_name)
        self.assertIsNotNone(channel)

        orgs = ["org1.example.com", "org2.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, 'Admin')
            response = self.client.channel_join(org_admin,
                                                self.channel_name,
                                                ['peer0.'+org, 'peer1.'+org],
                                                'orderer.example.com')
            self.assertTrue(response)
        logger.info("E2E: Channel join done: name={}".format(
            self.channel_name))

    def install_chaincode(self):

        pass

    def install_chaincode_fail(self):

        pass

    def instantiate_chaincode(self):

        pass

    def invoke_transaction(self):

        pass

    def query(self):

        pass

    def test_in_sequence(self):

        self.channel_create()
        self.channel_join()
        self.install_chaincode()
        self.install_chaincode_fail()
        self.instantiate_chaincode()
        self.invoke_transaction()
        self.query()


if __name__ == "__main__":
    unittest.main()
