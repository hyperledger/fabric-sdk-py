# Copyright IBM Corp. 2017 All Rights Reserved.
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

from hfc.fabric.channel.channel_configuration import ChannelConfiguration

CONFIG_FILE_PATH = os.path.join(
    os.path.dirname(__file__),
    '../../fixtures/e2e_cli/channel-artifacts/channel.tx')


class ChannelConfigurationTest(unittest.TestCase):
    """Test for channel configuration. """

    def setUp(self):
        self.file_path = CONFIG_FILE_PATH

    def test_create_channel_configuration_by_file(self):
        chan_conf = ChannelConfiguration(file_path=self.file_path)
        self.assertIsNotNone(chan_conf.config)

    def test_create_channel_configuration_by_bytes(self):
        with open(self.file_path, mode="rb") as file:
            config = file.read()

        chan_conf = ChannelConfiguration(config=config)
        self.assertIsNotNone(chan_conf.config)

    def test_create_channel_configuration(self):
        chan_conf = ChannelConfiguration()
        self.assertIsNone(chan_conf.config)

    def test_set_channel_configuration(self):
        chan_conf = ChannelConfiguration()
        self.assertIsNone(chan_conf.config)

        with open(self.file_path, mode="rb") as file:
            config = file.read()
        chan_conf.config = config
        self.assertIsNotNone(chan_conf.config)


if __name__ == '__main__':
    unittest.main()
