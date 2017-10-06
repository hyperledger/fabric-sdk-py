"""
# Copyright IBM Corp. 2017 All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
"""


import unittest
import logging
import os
import sys

from hfc.fabric.client import Client
from hfc.util.keyvaluestore import FileKeyValueStore

from test.unit.util import cli_call
from test.integration.config import E2E_CONFIG
from test.integration.e2e_utils import build_channel_request

logger = logging.getLogger(__name__)

if sys.version_info < (3, 0):
    from Queue import Queue
else:
    from queue import Queue


class E2eTest(unittest.TestCase):

    def setUp(self):

        self.base_path = "/tmp/fabric-sdk-py"
        self.kv_store_path = os.path.join(self.base_path, "key-value-store")
        self.client = Client()
        self.client.state_store = FileKeyValueStore(self.kv_store_path)
        self.channel_tx = \
            E2E_CONFIG['test-network']['channel-artifacts']['channel.tx']
        self.channel_name = \
            E2E_CONFIG['test-network']['channel-artifacts']['channel_id']
        self.compose_file_path = \
            E2E_CONFIG['test-network']['docker']['compose_file_tls']

        self.start_test_env()

    def tearDown(self):

        self.kv_store_path = None
        self.shutdown_test_env()

    def start_test_env(self):

        cli_call(["docker-compose", "-f", self.compose_file_path, "up", "-d"])

    def shutdown_test_env(self):

        cli_call(["docker-compose", "-f", self.compose_file_path, "down"])

    def create_channel(self):

        logger.info("start to create channel")
        request = build_channel_request(
            self.client,
            self.channel_tx,
            self.channel_name)

        q = Queue(1)
        response = self.client.create_channel(request)
        response.subscribe(on_next=lambda x: q.put(x),
                           on_error=lambda x: q.put(x))

        status, _ = q.get(timeout=5)

        try:
            self.assertEqual(status.status, 200)
        except AssertionError:
            logger.error("fail to create the channel with status code",
                         status.status)
            raise Exception("fail to create channel.")

        logger.info("successfully create the channel")

    def join_channel(self):

        pass

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
