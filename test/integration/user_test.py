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

import unittest
import time
import os

from test.unit.util import cli_call
from hfc.api.ca.caservice import ca_service
from hfc.api.user import User
from hfc.api.msp.msp import MSP
from hfc.api.crypto.crypto import ecies


USER_ID = 'user'
USER_PASSWD = 'userpw'


def get_submitter():
    ca = ca_service()
    msp = MSP('DEFAULT', ecies())
    user = User(USER_ID, USER_PASSWD, msp_impl=msp, ca=ca)
    user.enroll()

    return user


class UserTest(unittest.TestCase):

    def setUp(self):
        self.gopath_bak = os.environ.get('GOPATH', '')
        gopath = os.path.normpath(os.path.join(os.path.dirname(__file__),
                                               "../fixtures/chaincode"))
        os.environ['GOPATH'] = os.path.abspath(gopath)
        self.base_path = '/tmp/fabric-sdk-py'
        self.kv_store_path = os.path.join(self.base_path, 'key-value-store')
        self.compose_file_path = os.path.normpath(
            os.path.join(os.path.dirname(__file__),
                         "../fixtures/chaincode/docker-compose-simple.yml")
        )
        self.start_test_env()

    def tearDown(self):
        if self.gopath_bak:
            os.environ['GOPATH'] = self.gopath_bak
        self.shutdown_test_env()

    def start_test_env(self):
        cli_call(["docker-compose", "-f", self.compose_file_path, "up", "-d"])

    def shutdown_test_env(self):
        cli_call(["docker-compose", "-f", self.compose_file_path, "down"])

    def test_get_submitter(self):
        time.sleep(5)

        submitter = get_submitter()

        self.assertTrue(submitter.is_enrolled())

        # test the identity object carrying
        self.assertTrue(submitter.identity._certificate.
                        startswith(b"-----BEGIN CERTIFICATE-----"))


if __name__ == '__main__':
    unittest.main()
