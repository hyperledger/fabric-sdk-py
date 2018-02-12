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

from hfc.fabric.orderer import Orderer

DEFAULT_ORDERER_ENDPOINT = 'localhost:7050'
CUSTOM_ORDERER_ENDPOINT = 'orderer:7050'


class OrdererTest(unittest.TestCase):

    def setUp(self):
        self.custom_orderer_endpoint = CUSTOM_ORDERER_ENDPOINT
        self.deault_orderer_endpoint = DEFAULT_ORDERER_ENDPOINT

    def test_create_orderer_default_orderer(self):
        orderer = Orderer()
        self.assertEqual(orderer.endpoint, self.deault_orderer_endpoint)

    def test_create_orderer_custom_orderer(self):
        orderer = Orderer(endpoint=self.custom_orderer_endpoint)
        self.assertEqual(orderer.endpoint, self.custom_orderer_endpoint)


if __name__ == '__main__':
    unittest.main()
