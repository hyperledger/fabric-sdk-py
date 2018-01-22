"""
# Copyright IBM Corp. 2017 All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
"""


import unittest
import logging
import os
import sys
import time

from hfc.fabric.client import Client
from hfc.util.keyvaluestore import FileKeyValueStore

from test.integration.utils import cli_call
from test.integration.config import E2E_CONFIG
from test.integration.e2e_utils import build_channel_request, \
    build_join_channel_req

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
test_network = E2E_CONFIG['test-network']

if sys.version_info < (3, 0):
    from Queue import Queue
else:
    from queue import Queue


class E2eTest(unittest.TestCase):

    def setUp(self):

        self.base_path = "/tmp/fabric-sdk-py"
        self.kv_store_path = os.path.join(self.base_path, "key-value-store")
        self.channel_tx = \
            test_network['channel-artifacts']['channel.tx']
        self.channel_name = \
            test_network['channel-artifacts']['channel_id']
        self.compose_file_path = \
            test_network['docker']['compose_file_tls']
        self.client = Client(state_store=FileKeyValueStore(self.kv_store_path))

        self.start_test_env()

    def tearDown(self):

        self.kv_store_path = None
        self.shutdown_test_env()

    def start_test_env(self):

        cli_call(["docker-compose", "-f", self.compose_file_path, "up", "-d"])

    def shutdown_test_env(self):

        cli_call(["docker-compose", "-f", self.compose_file_path, "down"])

    def create_channel(self):

        client = Client(state_store=FileKeyValueStore(self.kv_store_path +
                                                      'build-channel'))

        logger.info("start to create channel")
        request = build_channel_request(
            client,
            self.channel_tx,
            self.channel_name)

        q = Queue(1)
        response = client.create_channel(request)
        response.subscribe(on_next=lambda x: q.put(x),
                           on_error=lambda x: q.put(x))

        status, _ = q.get(timeout=5)

        self.assertEqual(status.status, 200)

        logger.info("successfully create the channel: %s", self.channel_name)
        client.state_store = None

    def join_channel(self):

        # wait for channel created
        time.sleep(5)
        client = Client(state_store=FileKeyValueStore(self.kv_store_path +
                                                      'join-channel'))

        channel = client.new_channel(self.channel_name)

        logger.info("start to join channel")
        orgs = ["org1.example.com", "org2.example.com"]
        done = True
        for org in orgs:
            client.state_store = FileKeyValueStore(
                self.kv_store_path + org)
            request = build_join_channel_req(org, channel, client)
            done = done and channel.join_channel(request)
            if done:
                logger.info("peers in org: %s join channel: %s.",
                            org, self.channel_name)
        if done:
            logger.info("joining channel tested succefully.")
        client.state_store = None
        assert(done)

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

        self.create_channel()
        self.join_channel()
        self.install_chaincode()
        self.install_chaincode_fail()
        self.instantiate_chaincode()
        self.invoke_transaction()
        self.query()


if __name__ == "__main__":
    unittest.main()
