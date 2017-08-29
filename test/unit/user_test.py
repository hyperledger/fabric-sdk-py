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
import os
import unittest
from shutil import rmtree

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding

from hfc.fabric.user import User, Enrollment
from hfc.util.crypto.crypto import ecies
from hfc.util.keyvaluestore import file_key_value_store


class UserTest(unittest.TestCase):
    def setUp(self):
        self.base_path = '/tmp/fabric-sdk-py'
        self.path = os.path.join(self.base_path, 'user-state-store')

    def tearDown(self):
        rmtree(self.base_path)

    def test_create_user(self):
        store = file_key_value_store(self.path)
        user = User('test_user', 'peerOrg1', store)
        self.assertTrue(isinstance(user, User))

    def test_user_state(self):
        store = file_key_value_store(self.path)
        user = User('test_user', 'peerOrg1', store)
        user.roles = ['test']

        ec = ecies()

        enrollment = Enrollment(ec.generate_private_key(), "dasdasdasdasdasd")
        user.enrollment = enrollment

        user1 = User('test_user', 'peerOrg1', store)
        self.assertTrue(user1.roles == ['test'])
        self.assertTrue(user1.enrollment.cert == "dasdasdasdasdasd")
        pub_key = user1.enrollment.private_key.public_key()
        self.assertTrue(pub_key.public_bytes(
            encoding=Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
            .startswith(b'-----BEGIN PUBLIC KEY'))


if __name__ == '__main__':
    unittest.main()
