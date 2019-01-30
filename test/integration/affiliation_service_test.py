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


def get_affiliation():
    return ''.join([random.choice(string.digits) for n in range(9)])


class AffiliationServiceTest(unittest.TestCase):
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
        self._affiliationService = self._ca_service.newAffiliationService()

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
        affiliation = get_affiliation()
        res = self._affiliationService.create(self._adminEnrollment,
                                              affiliation)

        self.assertTrue(res['success'] is True)
        self.assertTrue(res['result']['name'] == affiliation)

    def test_getOne_success(self):
        """Test getOne success.
        """
        affiliation = get_affiliation()
        self._affiliationService.create(self._adminEnrollment, affiliation)

        res = self._affiliationService.getOne(affiliation,
                                              self._adminEnrollment)

        self.assertTrue(res['success'] is True)
        self.assertTrue(res['result']['name'] == affiliation)

    def test_getAll_success(self):
        """Test getAll success.
        """
        affiliation = get_affiliation()
        self._affiliationService.create(self._adminEnrollment, affiliation)

        res = self._affiliationService.getAll(self._adminEnrollment)

        self.assertTrue(res['success'] is True)
        self.assertTrue(len(res['result']['affiliations']) > 0)

    def test_delete_success(self):
        """Test delete success.
        """
        affiliation = get_affiliation()
        self._affiliationService.create(self._adminEnrollment, affiliation)

        res = self._affiliationService.delete(affiliation,
                                              self._adminEnrollment)

        self.assertTrue(res['success'] is True)

    def test_update_success(self):
        """Test update success.
        """
        affiliation = get_affiliation()
        self._affiliationService.create(self._adminEnrollment, affiliation)

        res = self._affiliationService.update(affiliation,
                                              self._adminEnrollment,
                                              name=affiliation + 'bis')

        self.assertTrue(res['success'] is True)
        self.assertTrue(res['result']['name'] == affiliation + 'bis')


if __name__ == '__main__':
    unittest.main()
