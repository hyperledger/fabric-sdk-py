# Copyright IBM Corp. 2016 All Rights Reserved.
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
import asyncio
import unittest
from hfc.fabric.client import Client


loop = asyncio.get_event_loop()


class ClientTest(unittest.TestCase):

    def setUp(self):
        self.client = Client('test/fixtures/network.json')

    def test_create_client(self):

        self.client.crypto_suite = 'my_crypto_suite'
        self.assertEqual(self.client.crypto_suite, 'my_crypto_suite')

        self.client.tx_context = 'my_tx_context'
        self.assertEqual(self.client.tx_context, 'my_tx_context')

        self.client.user_context = 'my_user_context'
        self.assertEqual(self.client.user_context, 'my_user_context')

        self.client.state_store = 'my_state_store'
        self.assertEqual(self.client.state_store, 'my_state_store')

    def test_new_channel(self):
        test_channel = self.client.new_channel('test')
        self.assertEqual(test_channel, self.client.get_channel('test'))

    def test_get_channel(self):
        test_channel = self.client.new_channel('test')
        self.assertEqual(test_channel, self.client.get_channel('test'))

        no_chain = self.client.get_channel('test1')
        self.assertIsNone(no_chain)

    def test_create_channel_missing_signatures(self):
        request = {}
        request['config'] = 'config'
        request['channel_name'] = 'channel_name'
        request['orderer'] = 'orderer'
        request['tx_id'] = 'tx_id'
        request['nonce'] = 'nonce'
        with self.assertRaises(ValueError):
            loop.run_until_complete(self.client._create_or_update_channel(
                request))

    def test_create_channel_not_list_of_signatures(self):
        request = {}
        request['config'] = 'config'
        request['signatures'] = 'signatures'
        request['channel_name'] = 'channel_name'
        request['orderer'] = 'orderer'
        request['tx_id'] = 'tx_id'
        request['nonce'] = 'nonce'
        with self.assertRaises(ValueError):
            loop.run_until_complete(self.client._create_or_update_channel(
                request))

    def test_create_channel_missing_tx_id(self):
        request = {}
        request['config'] = 'config'
        request['channel_name'] = 'channel_name'
        request['orderer'] = 'orderer'
        request['nonce'] = 'nonce'

        with self.assertRaises(ValueError):
            loop.run_until_complete(self.client._create_or_update_channel(
                request))

    def test_create_channel_missing_orderer(self):
        request = {}
        request['config'] = 'config'
        request['channel_name'] = 'channel_name'
        request['tx_id'] = 'tx_id'
        request['nonce'] = 'nonce'

        with self.assertRaises(ValueError):
            loop.run_until_complete(self.client._create_or_update_channel(
                request))

    def test_create_channel_missing_channel_name(self):
        request = {
            'config': 'config',
            'orderer': 'orderer',
            'tx_id': 'tx_id',
            'nonce': 'nonce',
        }

        with self.assertRaises(ValueError):
            loop.run_until_complete(self.client._create_or_update_channel(
                request))

    def test_export_network_profile(self):
        network_info = {
            "organizations": {
            },
            "orderers": {
            },
            "peers": {
            },
            "certificateAuthorities": {
            },
            'a': {
                'b': 'a.b'
            }
        }
        self.client.network_info = network_info
        self.client.export_net_profile('test-export.json')
        self.client.network_info = dict()
        self.client.init_with_net_profile('test-export.json')
        self.assertEqual(network_info, self.client.network_info)
        self.assertEqual('a.b', self.client.get_net_info('a', 'b'))

    def test_init_with_net_profile(self):
        self.client.init_with_net_profile('test/fixtures/network.json')
        self.assertEqual(self.client.get_net_info('organizations',
                                                  'orderer.example.com',
                                                  'mspid'), 'OrdererMSP',
                         "profile not match")


if __name__ == '__main__':
    unittest.main()
