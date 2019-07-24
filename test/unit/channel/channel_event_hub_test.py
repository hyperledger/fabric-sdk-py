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


class ChannelEventHubTest(unittest.TestCase):

    def setUp(self):
        super(ChannelEventHubTest, self).setUp()
        self.client = Client('test/fixtures/network.json')
        self.channel_name = "businesschannel"  # default application channel
        self.channel = self.client.new_channel(self.channel_name)
        self.blocks = []
        self.org = 'org1.example.com'
        self.peer = self.client.get_peer('peer0.' + self.org)
        self.org_admin = self.client.get_user(self.org, 'Admin')

        self.loop = asyncio.get_event_loop()

    def onEvent(self, block):
        self.blocks.append(block)

    def test_start_twice(self):
        channel_event_hub = self.channel.newChannelEventHub(self.peer,
                                                            self.org_admin)

        channel_event_hub.registerBlockEvent(start=0)

        with self.assertRaises(Exception) as e:
            channel_event_hub.connect(start=0)
        self.assertEqual('Not able to connect with start/stop block when a'
                         ' registered listener has those options.',
                         str(e.exception))

    def test_start_twice_from_listener(self):
        channel_event_hub = self.channel.newChannelEventHub(self.peer,
                                                            self.org_admin)

        s = channel_event_hub.connect(start=0, stop='newest')

        with self.assertRaises(Exception) as e:
            channel_event_hub.registerBlockEvent(start=0)

        try:
            self.loop.run_until_complete(s)  # will fail as no peer is running
        except Exception:
            pass

        channel_event_hub.disconnect()
        self.assertEqual('The registration with a start/stop block must be'
                         ' done before calling connect()', str(e.exception))

    def test_registered_before(self):
        channel_event_hub = self.channel.newChannelEventHub(self.peer,
                                                            self.org_admin)

        channel_event_hub.registerChaincodeEvent('foo', 'bar')

        with self.assertRaises(Exception) as e:
            channel_event_hub.registerBlockEvent(start=0)
        self.assertEqual('Only one event registration is allowed when'
                         ' start/stop block are used.',
                         str(e.exception))

    def test_start_bad_connect(self):
        channel_event_hub = self.channel.newChannelEventHub(self.peer,
                                                            self.org_admin)

        with self.assertRaises(Exception) as e:
            channel_event_hub.connect(start='foo')
        self.assertEqual('start value must be: last_seen, oldest, newest or'
                         ' an integer',
                         str(e.exception))

    def test_start_bad_listener(self):
        channel_event_hub = self.channel.newChannelEventHub(self.peer,
                                                            self.org_admin)

        with self.assertRaises(Exception) as e:
            channel_event_hub.registerBlockEvent(start='foo')
        self.assertEqual('start must be an integer',
                         str(e.exception))

    def test_stop_bad_listener(self):
        channel_event_hub = self.channel.newChannelEventHub(self.peer,
                                                            self.org_admin)

        with self.assertRaises(Exception) as e:
            channel_event_hub.registerBlockEvent(stop='foo')
        self.assertEqual('stop must be an integer, newest or sys.maxsize',
                         str(e.exception))

    def test_start_greater_connect(self):
        channel_event_hub = self.channel.newChannelEventHub(self.peer,
                                                            self.org_admin)

        with self.assertRaises(Exception) as e:
            channel_event_hub.connect(start=20, stop=10)
        self.assertEqual('start cannot be greater than stop',
                         str(e.exception))

    def test_start_greater_listener(self):
        channel_event_hub = self.channel.newChannelEventHub(self.peer,
                                                            self.org_admin)

        with self.assertRaises(Exception) as e:
            channel_event_hub.registerBlockEvent(start=20, stop=10)
        self.assertEqual('start cannot be greater than stop',
                         str(e.exception))


if __name__ == '__main__':
    unittest.main()
