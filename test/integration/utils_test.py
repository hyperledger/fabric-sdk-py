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
from hfc.fabric.client import Client
from hfc.fabric.transaction.tx_context import TXContext
from hfc.util.crypto.crypto import Ecies
from hfc.util import utils
from test.integration.utils import get_orderer_org_user
from test.integration.config import E2E_CONFIG
from hfc.protos.msp import identities_pb2
from hfc.protos.common import configtx_pb2
from hfc.protos.common import common_pb2
from google.protobuf.timestamp_pb2 import Timestamp


class UtilsTest(unittest.TestCase):
    def setUp(self):
        self.orderer_org_mspid = \
            E2E_CONFIG['test-network']['orderer']['mspid']
        self.channel_tx = \
            E2E_CONFIG['test-network']['channel-artifacts']['channel.tx']
        self.channel_id = \
            E2E_CONFIG['test-network']['channel-artifacts']['channel_id']
        self.base_path = "/tmp/fabric-sdk-py"
        self.kv_store_path = os.path.join(self.base_path, "key-value-store")

    def test_create_serialized_identity(self):
        client = Client('test/fixtures/network.json')

        orderer_org_admin = get_orderer_org_user(state_store=client.state_store
                                                 )
        orderer_org_admin_serialized = utils.create_serialized_identity(
            orderer_org_admin)
        serialized_identity = identities_pb2.SerializedIdentity()
        serialized_identity.ParseFromString(orderer_org_admin_serialized)

        self.assertEqual(serialized_identity.mspid,
                         self.orderer_org_mspid)

    def test_build_channel_header(self):
        timestamp = utils.current_timestamp()
        proto_channel_header = utils.build_channel_header(
            common_pb2.HeaderType.Value('CONFIG_UPDATE'),
            '12341234',
            self.channel_id,
            timestamp
        )

        self.assertIsInstance(proto_channel_header, common_pb2.ChannelHeader)
        self.assertEqual(proto_channel_header.channel_id, self.channel_id)

    def test_string_to_signature(self):
        with open(self.channel_tx, 'rb') as f:
            channel_tx = f.read()

        channel_config = utils.extract_channel_config(channel_tx)

        client = Client('test/fixtures/network.json')

        orderer_org_admin = get_orderer_org_user(state_store=client.state_store
                                                 )
        orderer_org_admin_tx_context = \
            TXContext(orderer_org_admin, Ecies(), {})
        client.tx_context = orderer_org_admin_tx_context

        orderer_org_admin_signature = client.sign_channel_config(
            channel_config
        )

        proto_signature = utils.string_to_signature(
            [orderer_org_admin_signature]
        )

        self.assertIsInstance(proto_signature, list)
        self.assertTrue(
            'OrdererMSP' in proto_signature[0].signature_header.__str__())

    def test_current_timestamp(self):
        my_timestamp = Timestamp()
        my_timestamp.GetCurrentTime()

        their_timestamp = utils.current_timestamp()
        self.assertEqual(my_timestamp.seconds, their_timestamp.seconds)

    def test_extract_channel_config(self):
        with open(self.channel_tx, 'rb') as f:
            channel_tx = f.read()

        config_update = configtx_pb2.ConfigUpdate()

        channel_config = utils.extract_channel_config(channel_tx)
        self.assertTrue(hasattr(channel_config, 'decode'))

        config_update.ParseFromString(channel_config)
        self.assertEqual(config_update.channel_id, self.channel_id)

    def test_build_header(self):
        timestamp = utils.current_timestamp()

        client = Client('test/fixtures/network.json')

        orderer_org_admin = get_orderer_org_user(state_store=client.state_store
                                                 )
        orderer_org_admin_tx_context = \
            TXContext(orderer_org_admin, Ecies(), {})
        client.tx_context = orderer_org_admin_tx_context

        orderer_org_admin_serialized = utils.create_serialized_identity(
            orderer_org_admin)
        serialized_identity = identities_pb2.SerializedIdentity()
        serialized_identity.ParseFromString(orderer_org_admin_serialized)

        proto_channel_header = utils.build_channel_header(
            common_pb2.HeaderType.Value('CONFIG_UPDATE'),
            orderer_org_admin_tx_context.tx_id,
            self.channel_id,
            timestamp
        )

        channel_header = utils.build_header(
            orderer_org_admin_tx_context.identity,
            proto_channel_header,
            orderer_org_admin_tx_context.nonce
        )
        self.assertIsInstance(channel_header, common_pb2.Header)


if __name__ == '__main__':
    unittest.main()
