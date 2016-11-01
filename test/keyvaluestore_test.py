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
import unittest
from shutil import rmtree

import rx

from hfs.util.keyvaluestore import file_key_value_store


class KeyValueStoreTest(unittest.TestCase):
    """Test for key value store. """

    def setUp(self):
        self.base_path = '/tmp/fabric-sdk-py'
        self.path = os.path.join(self.base_path, 'key-value-store')
        self.key = 'test'
        self.value = 'Hello world!'

    def tearDown(self):
        rmtree(self.base_path)

    def test_wrong_path(self):
        """Test illegal path. """
        path = os.path.join(self.base_path, 'wrong-path\0')
        with self.assertRaises(Exception):
            file_key_value_store(path)

    def test_write_and_read(self):
        """Test for setting and getting."""
        key_value_store = file_key_value_store(self.path)
        key_value_store.set_value(self.key, self.value)
        self.assertEqual(key_value_store.get_value(self.key), self.value)

    def test_async_write_and_read(self):
        """Test for async setting and getting."""
        key_value_store = file_key_value_store(self.path)
        key_value_store.async_set_value(self.key, self.value) \
            .flat_map(lambda x: key_value_store.async_get_value(self.key)) \
            .subscribe(rx.AnonymousObserver(
                lambda x: self.assertEqual(x, self.value)))


if __name__ == '__main__':
    unittest.main()
