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
import time
import unittest
import random
import string

from hfc.fabric_ca.caservice import CAService
from test.integration.utils import cli_call

with open(os.path.join(os.path.dirname(__file__),
                       "../fixtures/ca/enroll-csr.pem")) as f:
    test_pem = f.read()

ENROLLMENT_ID = "admin"
ENROLLMENT_SECRET = "adminpw"


def get_random_username():
    return ''.join(
        [random.choice(string.ascii_letters + string.digits)
         for n in range(9)])


class IdentityServiceTest(unittest.TestCase):
    """Test for ca module. """

    def setUp(self):
        self._enrollment_id = ENROLLMENT_ID
        self._enrollment_secret = ENROLLMENT_SECRET
        if os.getenv("CA_ADDR"):
            self._ca_server_address = os.getenv("CA_ADDR")
        else:
            self._ca_server_address = "localhost:7054"
        self.compose_file_path = os.path.normpath(
            os.path.join(os.path.dirname(__file__),
                         "../fixtures/ca/docker-compose.yml")
        )

        self.start_test_env()

        self._ca_service = CAService("http://" + self._ca_server_address)
        id = self._enrollment_id
        secret = self._enrollment_secret
        self._adminEnrollment = self._ca_service.enroll(id, secret)
        self._identityService = self._ca_service.newIdentityService()

    def tearDown(self):
        self.shutdown_test_env()

    def start_test_env(self):
        cli_call(["docker-compose", "-f", self.compose_file_path, "up", "-d"])
        time.sleep(5)

    def shutdown_test_env(self):
        cli_call(["docker-compose", "-f", self.compose_file_path, "down"])

    def test_create_success(self):
        """Test create success.
        """
        username = get_random_username()
        secret = self._identityService.create(self._adminEnrollment, username,
                                              enrollmentSecret='pass')
        self.assertTrue(secret == 'pass')

    def test_getOne_success(self):
        """Test getOne success.
        """
        username = get_random_username()
        self._identityService.create(self._adminEnrollment, username)

        res = self._identityService.getOne(username, self._adminEnrollment)
        self.assertTrue(res['result']['id'] == username)
        self.assertTrue(res['success'] is True)

    def test_getAll_success(self):
        """Test getAll success.
        """
        username = get_random_username()
        self._identityService.create(self._adminEnrollment, username)

        res = self._identityService.getAll(self._adminEnrollment)
        self.assertTrue(len(res['result']['identities']) > 0)
        self.assertTrue(res['success'] is True)

    def test_delete_success(self):
        """Test delete success.
        """
        username = get_random_username()
        self._identityService.create(self._adminEnrollment, username)

        res = self._identityService.delete(username, self._adminEnrollment)

        self.assertTrue(res['success'] is True)

    def test_update_success(self):
        """Test update success.
        """
        username = get_random_username()
        self._identityService.create(self._adminEnrollment, username)

        res = self._identityService.update(username, self._adminEnrollment,
                                           maxEnrollments=3)

        self.assertTrue(res['result']['id'] == username)
        self.assertTrue(res['result']['max_enrollments'] == 3)
        self.assertTrue(res['success'] is True)


if __name__ == '__main__':
    unittest.main()
