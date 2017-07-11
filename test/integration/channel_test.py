# Copyright 281165273@qq.com. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import os
import sys
import unittest
from time import sleep

from hfc.fabric.client import Client
from hfc.fabric.peer import create_peer
from hfc.fabric.transaction.tx_context import create_tx_context
from hfc.fabric.transaction.tx_proposal_request import create_tx_prop_req, \
    CC_INSTALL, CC_TYPE_GOLANG
from hfc.util.crypto.crypto import ecies
from hfc.util.keyvaluestore import file_key_value_store
from test.integration.e2e_config import E2E_CONFIG
from test.unit.util import get_peer_org_admin, cli_call

if sys.version_info < (3, 0):
    from Queue import Queue
else:
    from queue import Queue

CC_PATH = 'github.com/example_cc'
CC_NAME = 'example_cc'
CC_VERSION = 'v1'


class ClientTest(unittest.TestCase):
    """ Integration tests for the client module. """

    def setUp(self):
        self.gopath_bak = os.environ.get('GOPATH', '')
        gopath = os.path.normpath(os.path.join(os.path.dirname(__file__),
                                               "../../fixtures/chaincode"))
        os.environ['GOPATH'] = os.path.abspath(gopath)
        self.configtx_path = \
            E2E_CONFIG['test-network']['channel-artifacts']['channel.tx']
        self.peer0Org1_req_endpoint = E2E_CONFIG['test-network'][
            'org1.example.com']['peers']['peer0']['grpc_request_endpoint']
        self.peer0Org1_tls_certs = E2E_CONFIG['test-network'][
            'org1.example.com']['peers']['peer0']['tls_cacerts']
        self.peer0Org1_tls_hostname = E2E_CONFIG['test-network'][
            'org1.example.com']['peers']['peer0']['server_hostname']
        self.peer0Org2_req_endpoint = E2E_CONFIG['test-network'][
            'org2.example.com']['peers']['peer0']['grpc_request_endpoint']
        self.peer0Org2_tls_certs = E2E_CONFIG['test-network'][
            'org2.example.com']['peers']['peer0']['tls_cacerts']
        self.peer0Org2_tls_hostname = E2E_CONFIG['test-network'][
            'org2.example.com']['peers']['peer0']['server_hostname']
        self.compose_file_path = \
            E2E_CONFIG['test-network']['docker']['compose_file_tls']
        self.base_path = "/tmp/fabric-sdk-py"
        self.kv_store_path = os.path.join(self.base_path, "key-value-store")
        self.client = Client()
        self.start_test_env()

    def tearDown(self):
        if self.gopath_bak:
            os.environ['GOPATH'] = self.gopath_bak
        self.shutdown_test_env()

    def start_test_env(self):
        cli_call(["docker-compose", "-f", self.compose_file_path, "up", "-d"])

    def shutdown_test_env(self):
        cli_call(["docker-compose", "-f", self.compose_file_path, "down"])

    def test_install_chaincode_success(self):
        self.client.state_store = file_key_value_store(self.kv_store_path)

        with open(self.peer0Org1_tls_certs) as f:
            pem = f.read()

        opts = (
            ('grpc.ssl_target_name_override', self.peer0Org1_tls_hostname),)
        peer0_org1 = create_peer(endpoint=self.peer0Org1_req_endpoint,
                                 pem=pem, opts=opts)
        org1_admin = get_peer_org_admin(self.client, 'org1.example.com')

        crypto = ecies()
        tran_prop_req = create_tx_prop_req(CC_INSTALL, CC_PATH, CC_TYPE_GOLANG,
                                           CC_NAME, CC_VERSION)
        tx_context = create_tx_context(org1_admin, crypto, tran_prop_req)

        queue = Queue(1)

        sleep(5)
        response = self.client.send_install_proposal(tx_context, [peer0_org1])

        response.subscribe(
            on_next=lambda x: queue.put(x),
            on_error=lambda x: queue.put(x)
        )

        res = queue.get(timeout=5)
        proposal_response, _ = res[0][0]
        self.assertEqual(proposal_response.response.status, 200)


if __name__ == '__main__':
    unittest.main()
