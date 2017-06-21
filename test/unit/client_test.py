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

import unittest
import os
from hfc.fabric.client import Client
from hfc.util.keyvaluestore import file_key_value_store


class ClientTest(unittest.TestCase):

    def setUp(self):
        self.base_path = '/tmp/fabric-sdk-py'
        self.kv_store_path = os.path.join(self.base_path, 'key-value-store')

    @unittest.expectedFailure
    def test_create_client(self):
        # TODO impl

        client = Client()
        client.set_state_store(file_key_value_store(self.kv_store_path))
        self.fail()

    def test_create_new_chain(self):
        client = Client()
        client.set_state_store(file_key_value_store(self.kv_store_path))
        test_chain = client.new_chain('test')
        self.assertEqual(test_chain, client.get_chain('test'))

        no_chain = client.get_chain('test1')
        self.assertIsNone(no_chain)


if __name__ == '__main__':
    unittest.main()
