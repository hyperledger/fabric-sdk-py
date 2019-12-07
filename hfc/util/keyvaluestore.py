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
#
import os
from abc import ABCMeta, abstractmethod

import rx
import six


@six.add_metaclass(ABCMeta)
class KeyValueStore(object):
    """ An key value store for blockchain application state persistence. """

    @abstractmethod
    def set_value(self, key, value):
        """Set a value with a specific key.

        :param key: key
        :param value: value

        """

    @abstractmethod
    def get_value(self, key):
        """Get a value with a specific key.

        :param key: key

        :return: value
        """

    @abstractmethod
    def async_set_value(self, key, value, scheduler=None):
        """Set a value with a specific key.

        :param scheduler: scheduler
        :param key: key
        :param value: value

        :return:a future object
        """

    @abstractmethod
    def async_get_value(self, key, scheduler=None):
        """Get a value with a specific key.

        :param scheduler: scheduler
        :param key: key

        :return:a future object
        """


class FileKeyValueStore(KeyValueStore):
    """ A key value store implementation based file system. """

    def __init__(self, path):
        """Init the file key value store.

        :param path: path of key value store
        :return:
        """
        self.path = path
        _make_dir(path)

    def set_value(self, key, value):
        """Set a value with a specific key.

        Args:
            key: key
            value: value

        Returns: True when success
        Raises: File manipulate exceptions

        """
        file_path = os.path.join(self.path, key)
        with open(file_path, 'w') as f:
            f.write(value)
        return True

    def get_value(self, key):
        """Get a value with a specific key.

        :param key: key
        :return: value
        """
        try:
            file_path = os.path.join(self.path, key)
            with open(file_path) as f:
                return f.read()
        except IOError:
            return None

    def async_get_value(self, key, scheduler=None):
        """Get a value with a specific key.

        :param scheduler: scheduler
        :param key: key

        :return:a future object
        """
        return rx.start(lambda: self.get_value(key), scheduler)

    def async_set_value(self, key, value, scheduler=None):
        """Set a value with a specific key.

        :param scheduler: scheduler
        :param key: key
        :param value: value

        :return:a future object
        """
        return rx.start(lambda: self.set_value(key, value), scheduler)

    def get_attrs(self):
        return ",".join("{}={}"
                        .format(k, getattr(self, k))
                        for k in self.__dict__.keys())

    def __str__(self):
        return "[{}:{}]".format(self.__class__.__name__, self.get_attrs())


def _make_dir(path):
    try:
        os.makedirs(path)
    except OSError:
        if not os.path.isdir(path):
            raise


def file_key_value_store(path):
    """Factory method for creating file key value store.

    :param path: path

    :return an instance of file key value store
    """
    return FileKeyValueStore(path)
