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

from hfc.api.ca.caservice import CAClient, CAService
from test.unit.util import cli_call

with open(os.path.join(os.path.dirname(__file__),
                       "../fixtures/ca/enroll-csr.pem")) as f:
    test_pem = f.read()

ENROLLMENT_ID = "admin"
ENROLLMENT_SECRET = "adminpw"


class CATest(unittest.TestCase):
    """Test for ca module. """

    def setUp(self):
        self._enrollment_id = ENROLLMENT_ID
        self._enrollment_secret = ENROLLMENT_SECRET
        # self._enrollment_id = "testUser"
        # self._enrollment_secret = "user1"
        if os.getenv("CA_ADDR"):
            self._ca_server_address = os.getenv("CA_ADDR")
        else:
            self._ca_server_address = "localhost:7054"
        self.compose_file_path = os.path.normpath(
            os.path.join(os.path.dirname(__file__),
                         "../fixtures/ca/docker-compose.yml")
        )
        self.start_test_env()

    def tearDown(self):
        self.shutdown_test_env()

    def start_test_env(self):
        cli_call(["docker-compose", "-f", self.compose_file_path, "up", "-d"])

    # @staticmethod
    def shutdown_test_env(self):
        cli_call(["docker-compose", "-f", self.compose_file_path, "down"])

    def test_get_ca_info(self):
        time.sleep(1)
        ca_client = CAClient("http://" + self._ca_server_address)
        ca_chain = ca_client.get_cainfo()
        self.assertTrue(ca_chain.startswith(b"-----BEGIN CERTIFICATE-----"))

    def test_enroll_missing_enrollment_id(self):
        """Test enroll missing enrollment id.
        """
        ca_client = CAClient("http://" + self._ca_server_address)
        self._enrollment_id = ""
        with self.assertRaises(ValueError):
            ca_client.enroll(self._enrollment_id,
                             self._enrollment_secret, test_pem)

    def test_enroll_missing_enrollment_secret(self):
        """Test enroll missing enrollment secret.
        """
        ca_client = CAClient("http://" + self._ca_server_address)
        self._enrollment_secret = ""
        with self.assertRaises(ValueError):
            ca_client.enroll(self._enrollment_id,
                             self._enrollment_secret, test_pem)

    def test_enroll_missing_enrollment_csr(self):
        """Test enroll missing enrollment csr.
        """
        ca_client = CAClient("http://" + self._ca_server_address)
        with self.assertRaises(ValueError):
            ca_client.enroll(self._enrollment_id,
                             self._enrollment_secret, "")

    def test_enroll_success(self):
        """Test enroll success.
        """
        time.sleep(5)
        ca_client = CAClient("http://" + self._ca_server_address)
        ecert = ca_client.enroll(self._enrollment_id,
                                 self._enrollment_secret, test_pem)
        self.assertTrue(ecert.startswith(b"-----BEGIN CERTIFICATE-----"))

    def test_enroll_unreachable_server_address(self):
        """Test enroll unreachable server address.
        """
        self._ca_server_address = "test:80"
        ca_client = CAClient("http://" + self._ca_server_address)
        with self.assertRaises(Exception):
            ca_client.enroll(self._enrollment_id,
                             self._enrollment_secret, test_pem)

    def test_enroll_invalid_server_address(self):
        """Test enroll invalid server address.
        """
        self._ca_server_address = "test:80:90"
        ca_client = CAClient("http://" + self._ca_server_address)
        with self.assertRaises(RequestException):
            ca_client.enroll(self._enrollment_id,
                             self._enrollment_secret, test_pem)

    def test_enroll_with_generated_csr_success(self):
        """Test enroll with generated csr success.
        """
        time.sleep(5)
        ca_service = CAService("http://" + self._ca_server_address)
        key, ecert = ca_service.enroll(self._enrollment_id,
                                       self._enrollment_secret)
        self.assertTrue(ecert.startswith(b"-----BEGIN CERTIFICATE-----"))


if __name__ == '__main__':
    unittest.main()
