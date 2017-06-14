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


class ChannelConfiguration(object):
    """A class represents channel configuration bytes."""

    def __init__(self, config=None, file_path=None):
        """Construct ChannelConfiguration by args.

        Args:
            config: raw config bytes
            file_path: config file path
        """
        self._config = None

        if file_path:
            with open(file_path, mode='rb') as file:
                self._config = file.read()

        if config:
            self._config = config

    @property
    def config(self):
        """Get config bytes.

        Returns: raw config bytes

        """
        return self._config

    @config.setter
    def config(self, config):
        """Set config bytes.

        Args:
            config: raw config bytes
        """
        self._config = config
