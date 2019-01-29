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

from hfc.fabric_ca.caservice import CAClient, Enrollment, CAService
from hfc.util.crypto.crypto import ecies

with open(os.path.join(os.path.dirname(__file__),
                       "../fixtures/ca/enroll-csr.pem")) as f:
    test_pem = f.read()

ENROLLMENT_ID = "admin"
ENROLLMENT_SECRET = "adminpw"

private_key = ecies().generate_private_key()


class CATest(unittest.TestCase):
    """Test for ca module. """

    def setUp(self):
        self._enrollment_id = ENROLLMENT_ID
        self._enrollment_secret = ENROLLMENT_SECRET
        if os.getenv("CA_ADDR"):
            self._ca_server_address = os.getenv("CA_ADDR")
        else:
            self._ca_server_address = "localhost:7054"

        # get an enrollment for registering
        self._enrollment = Enrollment(None, '', '')

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

    def test_register_missing_enrollment_id(self):
        """Test register missing enrollment id.
        """
        with self.assertRaises(ValueError):
            self._enrollment.register('')

    def test_register_wrong_maxEnrollments(self):
        """Test register wrong maxEnrollments.
        """
        with self.assertRaises(ValueError):
            self._enrollment.register('foo', maxEnrollments='bar')

    def test_register_unreachable_server_address(self):
        """Test register unreachable server address.
        """
        self._ca_server_address = "test:80"
        ca_service = CAService("http://" + self._ca_server_address)
        enrollment = Enrollment(None, '', ca_service)
        with self.assertRaises(Exception):
            enrollment.register('foo')

    def test_revoke_missing_enrollment_id(self):
        """Test revoke missing enrollment id.
        """
        with self.assertRaises(ValueError):
            self._enrollment.revoke()

    def test_revoke_missing_aki(self):
        """Test revoke missing aki.
        """
        serial = 'c8bd471cfd8ea393ecf5c35099ad3c074920652'
        with self.assertRaises(ValueError):
            self._enrollment.revoke(aki=None, serial=serial)

    def test_revoke_missing_serial(self):
        """Test revoke missing serial.
        """
        aki = '7943138249940b7255d4bd020e7071d31b9c16ed'
        with self.assertRaises(ValueError):
            self._enrollment.revoke(aki=aki, serial=None)

    def test_revoke_wrong_reason(self):
        """Test revoke wrong reason.
        """
        reason = 'foo'
        with self.assertRaises(ValueError):
            self._enrollment.revoke('user', reason=reason)

    def test_revoke_unreachable_server_address(self):
        """Test revoke unreachable server address.
        """
        self._ca_server_address = "test:80"
        ca_service = CAService("http://" + self._ca_server_address)
        enrollment = Enrollment(None, '', ca_service)
        with self.assertRaises(Exception):
            enrollment.revoke('foo')

    def test_reenroll_no_user(self):
        """Test reenroll no user
        """
        ca_service = CAService("http://" + self._ca_server_address)
        with self.assertRaises(ValueError):
            ca_service.reenroll('foo')

    def test_reenroll_wrong_attr_req(self):
        """Test reenroll wrong attr_req
        """
        ca_service = CAService("http://" + self._ca_server_address)
        with self.assertRaises(AttributeError):
            ca_service.reenroll(self._enrollment, [''])

    def test_reenroll_unreachable_server_address(self):
        """Test reenroll unreachable server address.
        """
        self._ca_server_address = "test:80"
        ca_service = CAService("http://" + self._ca_server_address)
        with self.assertRaises(Exception):
            ca_service.reenroll(self._enrollment)


if __name__ == '__main__':
    unittest.main()
