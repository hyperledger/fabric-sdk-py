# Copyright 2009-2017 SAP SE or an SAP affiliate company.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import unittest
import sys

from hfc.util.utils import extract_channel_config
from hfc.fabric.client import Client
from hfc.util.keyvaluestore import FileKeyValueStore
from hfc.fabric.orderer import Orderer
from test.integration.e2e_config import E2E_CONFIG
from test.unit.util import get_peer_org_admin, get_orderer_org_admin, cli_call
from hfc.fabric.tx_context import TXContext
from hfc.util.crypto.crypto import Ecies


if sys.version_info < (3, 0):
    from Queue import Queue
else:
    from queue import Queue


class ClientTest(unittest.TestCase):
    """ Integration tests for the client module. """

    def setUp(self):
        self.configtx_path = \
            E2E_CONFIG['test-network']['channel-artifacts']['channel.tx']
        self.orderer_tls_certs = \
            E2E_CONFIG['test-network']['orderer']['tls_cacerts']
        self.orderer_tls_hostname = \
            E2E_CONFIG['test-network']['orderer']['server_hostname']
        self.compose_file_path = \
            E2E_CONFIG['test-network']['docker']['compose_file_tls']
        self.base_path = "/tmp/fabric-sdk-py"
        self.kv_store_path = os.path.join(self.base_path, "key-value-store")
        self.client = Client()
        self.start_test_env()

    def tearDown(self):
        self.shutdown_test_env()

    def start_test_env(self):
        cli_call(["docker-compose", "-f", self.compose_file_path, "up", "-d"])

    def shutdown_test_env(self):
        cli_call(["docker-compose", "-f", self.compose_file_path, "down"])

    def test_create_channel_missing_signatures(self):
        signatures = []

        self.client.state_store = FileKeyValueStore(self.kv_store_path)

        with open(self.orderer_tls_certs) as f:
            pem = f.read()

        opts = (('grpc.ssl_target_name_override', 'orderer.example.com'),)
        orderer = Orderer(pem=pem, opts=opts)

        with open(self.configtx_path, 'rb') as f:
            envelope = f.read()

        # convert envelope to config
        config = extract_channel_config(envelope)

        channel_name = 'businesschannel'

        # signatures orderer admin
        orderer_admin = get_orderer_org_admin(self.client)
        orderer_admin_tx_context = TXContext(orderer_admin, Ecies())
        self.client.tx_context = orderer_admin_tx_context

        orderer_admin_signature = self.client.sign_channel_config(config)
        orderer_admin_signature.SerializeToString()

        # take the tx_id and nonce from the oderer user context
        tx_id = orderer_admin_tx_context.tx_id
        nonce = orderer_admin_tx_context.nonce

        # reset the state store to handle different
        # users with one client object
        self.client.state_store = FileKeyValueStore(self.kv_store_path)

        # signatures org1 admin
        org1_admin = get_peer_org_admin(self.client, 'org1.example.com')
        org1_admin_tx_context = TXContext(org1_admin, Ecies())
        self.client.tx_context = org1_admin_tx_context

        org1_admin_signature = self.client.sign_channel_config(config)
        org1_admin_signature.SerializeToString()

        # reset the state store to handle different
        # users with one client object
        self.client.state_store = FileKeyValueStore(self.kv_store_path)

        # signatures org2 admin
        org2_admin = get_peer_org_admin(self.client, 'org2.example.com')
        org2_admin_tx_context = TXContext(org2_admin, Ecies())
        self.client.tx_context = org2_admin_tx_context

        org2_admin_signature = self.client.sign_channel_config(config)
        org2_admin_signature.SerializeToString()

        request = {
            'tx_id': tx_id,
            'nonce': nonce,
            'signatures': signatures,
            'config': config,
            'orderer': orderer,
            'channel_name': channel_name
        }

        queue = Queue(1)

        response = self.client.create_channel(request)

        response.subscribe(
            on_next=lambda x: queue.put(x),
            on_error=lambda x: queue.put(x)
        )

        status, _ = queue.get(timeout=5)
        self.assertEqual(status.status, 400)

    def test_create_channel(self):
        signatures = []

        self.client.state_store = FileKeyValueStore(self.kv_store_path)

        with open(self.orderer_tls_certs) as f:
            pem = f.read()

        opts = (('grpc.ssl_target_name_override', 'orderer.example.com'),)
        orderer = Orderer(pem=pem, opts=opts)

        with open(self.configtx_path, 'rb') as f:
            envelope = f.read()

        # convert envelope to config
        config = extract_channel_config(envelope)

        channel_name = 'businesschannel'

        # signatures orderer admin
        orderer_admin = get_orderer_org_admin(self.client)
        orderer_admin_tx_context = TXContext(orderer_admin, Ecies())
        self.client.tx_context = orderer_admin_tx_context

        orderer_admin_signature = self.client.sign_channel_config(config)
        orderer_admin_signature_bytes = \
            orderer_admin_signature.SerializeToString()

        # take the tx_id and nonce from the oderer user context
        tx_id = orderer_admin_tx_context.tx_id
        nonce = orderer_admin_tx_context.nonce

        # append orderer_org_admin signatures
        signatures.append(orderer_admin_signature_bytes)

        # reset the state store to handle different
        # users with one client object
        self.client.state_store = FileKeyValueStore(self.kv_store_path)

        # signatures org1 admin
        org1_admin = get_peer_org_admin(self.client, 'org1.example.com')
        org1_admin_tx_context = TXContext(org1_admin, Ecies())
        self.client.tx_context = org1_admin_tx_context

        org1_admin_signature = self.client.sign_channel_config(config)
        org1_admin_signature_bytes = org1_admin_signature.SerializeToString()

        # append org1_admin_signature to signatures
        signatures.append(org1_admin_signature_bytes)

        # reset the state store to handle different
        # users with one client object
        self.client.state_store = FileKeyValueStore(self.kv_store_path)

        # signatures org2 admin
        org2_admin = get_peer_org_admin(self.client, 'org2.example.com')
        org2_admin_tx_context = TXContext(org2_admin, Ecies())
        self.client.tx_context = org2_admin_tx_context

        org2_admin_signature = self.client.sign_channel_config(config)
        org2_admin_signature_bytes = org2_admin_signature.SerializeToString()

        # append org1_admin_signature to signatures
        signatures.append(org2_admin_signature_bytes)

        request = {
            'tx_id': tx_id,
            'nonce': nonce,
            'signatures': signatures,
            'config': config,
            'orderer': orderer,
            'channel_name': channel_name
        }
        response = self.client.create_channel(request)

        q = Queue(1)
        response.subscribe(on_next=lambda x: q.put(x),
                           on_error=lambda x: q.put(x))

        status, _ = q.get(timeout=5)
        self.assertEqual(status.status, 200)

    @unittest.skip
    def test_create_channel_with_envelope(self):
        # TODO missing impl
        # signed envelope necessary
        pass


if __name__ == '__main__':
    unittest.main()
