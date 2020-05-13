# SPDX-License-Identifier: Apache-2.0

import os
import unittest
import time

from test.integration.utils import cli_call

from hfc.fabric_ca.caservice import ca_service
from hfc.fabric_network.couchdbwalletstore import CouchDBWalletStore

ENROLLMENT_ID = "admin"
ENROLLMENT_SECRET = "adminpw"
DB_NAME = 'wallet'


class WalletTest(unittest.TestCase):
    def setUp(self):
        self._enrollment_id = ENROLLMENT_ID
        self._enrollment_secret = ENROLLMENT_SECRET
        self._dbName = DB_NAME
        if os.getenv("CA_ADDR"):
            self._ca_server_address = os.getenv("CA_ADDR")
        else:
            self._ca_server_address = "localhost:7054"
        self._compose_file_path = os.path.normpath(
            os.path.join(os.path.dirname(__file__),
                         "../fixtures/ca/docker-compose.yml")
        )
        self._couch_compose_file_path = os.path.normpath(
            os.path.join(os.path.dirname(__file__),
                         "../fixtures/docker-compose-couch.yaml")
        )
        self.start_test_env()

    def tearDown(self):
        self.shutdown_test_env()

    def start_test_env(self):
        cli_call(["docker-compose", "-f", self._compose_file_path, "up", "-d"])
        cli_call(["docker-compose", "-f", self._couch_compose_file_path, "up", "-d"])
        time.sleep(5)

    def shutdown_test_env(self):
        cli_call(["docker-compose", "-f", self._compose_file_path, "down"])
        cli_call(["docker-compose", "-f", self._couch_compose_file_path, "down"])

    def test_enroll(self):
        casvc = ca_service("http://" + self._ca_server_address)
        adminEnrollment = casvc.enroll(self._enrollment_id,
                                       self._enrollment_secret)
        config = 'http://localhost:5984'
        server = CouchDBWalletStore(DB_NAME, config)
        server.put(self._enrollment_id, adminEnrollment)

        self.assertTrue(server.exists(self._enrollment_id))

        server.remove(self._enrollment_id)

        self.assertFalse(server.exists(self._enrollment_id))


if __name__ == '__main__':
    unittest.main()
