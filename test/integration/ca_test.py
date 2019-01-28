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

from hfc.fabric_ca.caservice import CAClient, CAService
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


class CATest(unittest.TestCase):
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

    def tearDown(self):
        self.shutdown_test_env()

    def start_test_env(self):
        cli_call(["docker-compose", "-f", self.compose_file_path, "up", "-d"])
        time.sleep(5)

    def shutdown_test_env(self):
        cli_call(["docker-compose", "-f", self.compose_file_path, "down"])

    def test_get_ca_info(self):
        ca_client = CAClient("http://" + self._ca_server_address)
        ca_chain = ca_client.get_cainfo()
        self.assertTrue(ca_chain.startswith(b"-----BEGIN CERTIFICATE-----"))

    def test_enroll_success(self):
        """Test enroll success.
        """
        ca_client = CAClient("http://" + self._ca_server_address)
        enrollmentCert, caCertChain = ca_client.enroll(self._enrollment_id,
                                                       self._enrollment_secret,
                                                       test_pem)
        self.assertTrue(enrollmentCert
                        .startswith(b"-----BEGIN CERTIFICATE-----"))
        self.assertTrue(caCertChain.startswith(b"-----BEGIN CERTIFICATE-----"))

    def test_enroll_with_generated_csr_success(self):
        """Test enroll with generated csr success.
        """
        ca_service = CAService("http://" + self._ca_server_address)
        enrollment = ca_service.enroll(self._enrollment_id,
                                       self._enrollment_secret)
        self.assertTrue(enrollment.cert
                        .startswith(b"-----BEGIN CERTIFICATE-----"))

    def test_register_success(self):
        """Test register success.
        """
        ca_service = CAService("http://" + self._ca_server_address)
        enrollment = ca_service.enroll(self._enrollment_id,
                                       self._enrollment_secret)
        # use a random username for registering for avoiding already register
        # issues when test suite ran several times
        username = get_random_username()
        secret = enrollment.register(username, 'pass')
        self.assertTrue(secret == 'pass')

    def test_register_without_password_success(self):
        """Test register without password success.
        """
        ca_service = CAService("http://" + self._ca_server_address)
        enrollment = ca_service.enroll(self._enrollment_id,
                                       self._enrollment_secret)
        # use a random username for registering for avoiding already register
        # issues when test suite ran several times
        username = get_random_username()
        secret = enrollment.register(username)
        self.assertTrue(len(secret) == 12)

    def test_already_register(self):
        """Test register a second time.
        """
        ca_service = CAService("http://" + self._ca_server_address)
        enrollment = ca_service.enroll(self._enrollment_id,
                                       self._enrollment_secret)
        # use a random username for registering for avoiding already register
        # issues when test suite ran several times
        username = get_random_username()
        enrollment.register(username)

        # register a second time
        with self.assertRaises(Exception):
            enrollment.register(username)

    def test_revoke_success(self):
        """Test revoke success.
        """
        ca_service = CAService("http://" + self._ca_server_address)
        enrollment = ca_service.enroll(self._enrollment_id,
                                       self._enrollment_secret)
        # use a random username for registering for avoiding already register
        # issues when test suite ran several times
        username = get_random_username()
        secret = enrollment.register(username)

        # enroll new user
        ca_service.enroll(username, secret)

        # now revoke
        RevokedCerts, CRL = enrollment.revoke(username)
        self.assertTrue(CRL == '')
        self.assertTrue(len(RevokedCerts) == 1)
        self.assertTrue('Serial' in RevokedCerts[0])
        self.assertTrue('AKI' in RevokedCerts[0])
        self.assertTrue(len(RevokedCerts[0]['AKI']) > 0)
        self.assertTrue(len(RevokedCerts[0]['Serial']) > 0)

    def test_reenroll_success(self):
        """Test revoke success.
        """
        ca_service = CAService("http://" + self._ca_server_address)
        enrollment = ca_service.enroll(self._enrollment_id,
                                       self._enrollment_secret)
        # use a random username for registering for avoiding already register
        # issues when test suite ran several times
        username = get_random_username()
        secret = enrollment.register(username)

        # enroll new user
        enrollment = ca_service.enroll(username, secret)

        # reenroll
        reenrollment = ca_service.reenroll(enrollment)

        self.assertTrue(reenrollment.cert
                        .startswith(b"-----BEGIN CERTIFICATE-----"))

    def test_reenroll_after_revoke_success(self):
        """Test revoke success.
        """
        ca_service = CAService("http://" + self._ca_server_address)
        enrollment = ca_service.enroll(self._enrollment_id,
                                       self._enrollment_secret)
        # use a random username for registering for avoiding already register
        # issues when test suite ran several times
        username = get_random_username()
        secret = enrollment.register(username)

        # enroll new user
        enrollment = ca_service.enroll(username, secret)

        # now revoke
        enrollment.revoke(username)

        # reenroll
        with self.assertRaises(Exception):
            ca_service.reenroll(enrollment)

    def test_genCRL_success(self):
        """Test revoke success.
        """
        ca_service = CAService("http://" + self._ca_server_address)
        enrollment = ca_service.enroll(self._enrollment_id,
                                       self._enrollment_secret)
        # use a random username for registering for avoiding already register
        # issues when test suite ran several times
        username = get_random_username()
        secret = enrollment.register(username)

        # enroll new user
        ca_service.enroll(username, secret)

        # now revoke
        enrollment.revoke(username)

        # gen CRL
        try:
            enrollment.generateCRL()
        except Exception as e:
            self.fail("generateCRL fails: {0}".format(e))


if __name__ == '__main__':
    unittest.main()
