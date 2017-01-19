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

from requests.exceptions import RequestException

from hfc.api.cop.copservice import COPClient, COPService
from test.unit.util import cli_call

with open(os.path.join(os.path.dirname(__file__),
                       "../fixtures/cop/enroll-csr.pem")) as f:
    test_pem = f.read()


class COPTest(unittest.TestCase):
    """Test for cop module. """

    def setUp(self):
        self._enrollment_id = "testUser"
        self._enrollment_secret = "user1"
        if os.getenv("COP_ADDR"):
            self._cop_server_address = os.getenv("COP_ADDR")
        else:
            self._cop_server_address = "localhost:8888"

    @staticmethod
    def start_test_env():
        cli_call(["docker-compose", "-f",
                  os.path.join(os.path.dirname(__file__),
                               "../fixtures/cop/docker-compose.yml"),
                  "up", "-d"])

    @staticmethod
    def shutdown_test_env():
        cli_call(["docker-compose", "-f",
                  os.path.join(os.path.dirname(__file__),
                               "../fixtures/cop/docker-compose.yml"),
                  "down"])

    def test_enroll_missing_enrollment_id(self):
        """Test enroll missing enrollment id.
        """
        cop_client = COPClient("http://" + self._cop_server_address)
        self._enrollment_id = ""
        with self.assertRaises(ValueError):
            cop_client.enroll(self._enrollment_id,
                              self._enrollment_secret, test_pem)

    def test_enroll_missing_enrollment_secret(self):
        """Test enroll missing enrollment secret.
        """
        cop_client = COPClient("http://" + self._cop_server_address)
        self._enrollment_secret = ""
        with self.assertRaises(ValueError):
            cop_client.enroll(self._enrollment_id,
                              self._enrollment_secret, test_pem)

    def test_enroll_missing_enrollment_csr(self):
        """Test enroll missing enrollment csr.
        """
        cop_client = COPClient("http://" + self._cop_server_address)
        with self.assertRaises(ValueError):
            cop_client.enroll(self._enrollment_id,
                              self._enrollment_secret, "")

    def test_enroll_success(self):
        """Test enroll success.
        """
        self.shutdown_test_env()
        self.start_test_env()
        time.sleep(5)
        cop_client = COPClient("http://" + self._cop_server_address)
        ecert = cop_client.enroll(self._enrollment_id,
                                  self._enrollment_secret, test_pem)
        self.assertTrue(ecert.startswith(b"-----BEGIN CERTIFICATE-----"))
        self.shutdown_test_env()

    def test_enroll_unreachable_server_address(self):
        """Test enroll unreachable server address.
        """
        self._cop_server_address = "test:80"
        cop_client = COPClient("http://" + self._cop_server_address)
        with self.assertRaises(Exception):
            cop_client.enroll(self._enrollment_id,
                              self._enrollment_secret, test_pem)

    def test_enroll_invalid_server_address(self):
        """Test enroll invalid server address.
        """
        self._cop_server_address = "test:80:90"
        cop_client = COPClient("http://" + self._cop_server_address)
        with self.assertRaises(RequestException):
            cop_client.enroll(self._enrollment_id,
                              self._enrollment_secret, test_pem)

    def test_enroll_with_generated_csr_success(self):
        """Test enroll with generated csr success.
        """
        self.shutdown_test_env()
        self.start_test_env()
        time.sleep(5)
        cop_service = COPService("http://" + self._cop_server_address)
        ecert = cop_service.enroll(self._enrollment_id,
                                   self._enrollment_secret)
        self.assertTrue(ecert.startswith(b"-----BEGIN CERTIFICATE-----"))
        self.shutdown_test_env()


if __name__ == '__main__':
    unittest.main()
