# Copyright esse.io 2016 All Rights Reserved.
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


class Client(object):
    """
        Main interaction handler with end user.
        Client can maintain several chains.
    """

    def new_chain(self, chain_name):
        """Init a chain instance with given name.

        :param chain_name: The name of chain

        :return: The inited chain instance
        """

        pass

    def get_chain(self, chain_name):
        """ Get a chain instance

        :param chain_name: the name of the chain

        :return: Get the chain instance with the name or None
        """
        pass

    def set_KeyValueStore(self, store):
        """store user enrollment materials. The SDK should make this
        pluggable so that different store implementations can be
        selected by the application. For instance, in some cases
        File-based stores a sufficient. But for clustering purposes,
        multiple application instances want to share a store backed
        by a database.

        :param store: instance of an alternative KeyValueStore
        implementation provided by the consuming app

        :return: None
        """

        pass

    def set_logger(self, logger):
        """Sets an instance of a logger used by the consuming application.
        This is useful because an application would likely want to use a
        common logger for all parts of the code.
        And typically an IT organization would have log scraping set up for
        monitoring and analytics purposes, such that a “standard” log format
        is desirable.
        The SDK should have a built-in logger so that developers get logging by
        default.
        But it MUST allow an external logger to be set with a standard set of
        logging APIs

        :param logger: an external logging utility that implements a standard
        interface.

        :return: None
        """
        pass

    def Key_related_process(self, name):
        """TODO.
        store or change persistent and private data
        Params

        :param name:The name of the key
        :return: the result

        """
        pass
