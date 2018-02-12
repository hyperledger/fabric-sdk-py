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

import sys
import time
import unittest

from test.integration.utils import BaseTestCase

if sys.version_info < (3, 0):
    from Queue import Queue
else:
    from queue import Queue


class ChannelCreateTest(BaseTestCase):
    """ Integration tests for the channel related operations.
    """

    def setUp(self):
        super(ChannelCreateTest, self).setUp()

    def test_channel_create(self):
        time.sleep(5)  # wait the network starts
        q = Queue(1)
        response = self.client.create_channel('orderer.example.com',
                                              self.channel_name, self.user,
                                              self.channel_tx)
        response.subscribe(on_next=lambda x: q.put(x),
                           on_error=lambda x: q.put(x))

        status, _ = q.get(timeout=5)
        self.assertEqual(status.status, 200)


if __name__ == '__main__':
    unittest.main()
