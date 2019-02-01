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

from hfc.fabric_ca.caservice import CAService
from test.integration.utils import cli_call

with open(os.path.join(os.path.dirname(__file__),
                       "../fixtures/ca/enroll-csr.pem")) as f:
    test_pem = f.read()

ENROLLMENT_ID = "admin"
ENROLLMENT_SECRET = "adminpw"


class CertificateServiceTest(unittest.TestCase):
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
        self._certificateService = self._ca_service.newCertificateService()

    def tearDown(self):
        self.shutdown_test_env()

    def start_test_env(self):
        cli_call(["docker-compose", "-f", self.compose_file_path, "up", "-d"])
        time.sleep(5)

    def shutdown_test_env(self):
        cli_call(["docker-compose", "-f", self.compose_file_path, "down"])

    def test_get_success(self):
        """Test create success.
        """
        res = self._certificateService.getCertificates(self._adminEnrollment)

        self.assertTrue(res['success'] is True)
        self.assertTrue(len(res['result']) > 0)


if __name__ == '__main__':
    unittest.main()
