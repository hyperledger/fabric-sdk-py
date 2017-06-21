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

from requests.exceptions import RequestException

from hfc.fabric_ca.caservice import CAClient

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
        if os.getenv("CA_ADDR"):
            self._ca_server_address = os.getenv("CA_ADDR")
        else:
            self._ca_server_address = "localhost:7054"

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


if __name__ == '__main__':
    unittest.main()
