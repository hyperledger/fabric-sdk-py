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
from hfc.fabric.peer import Peer

DEFAULT_PEER_ENDPOINT = 'localhost:7051'
CUSTOM_PEER_ENDPOINT = 'peer:7051'


class PeerTest(unittest.TestCase):

    def setUp(self):
        self.default_peer_endpoint = DEFAULT_PEER_ENDPOINT
        self.custom_peer_endpoint = CUSTOM_PEER_ENDPOINT

    def test_create_peer_default_endpoint(self):
        peer = Peer()
        self.assertEqual(peer.endpoint, self.default_peer_endpoint)

    def test_create_peer_custom_endpoint(self):
        peer = Peer(name="test_peer", endpoint=self.custom_peer_endpoint)
        self.assertEqual(peer.endpoint, self.custom_peer_endpoint)


if __name__ == '__main__':
    unittest.main()
