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

from hfc.api.client import Client
from hfc.api.user import User
from hfc.api.msp import msp

"""
config data for build the channel
"""
test_input  = {}

class CreateChannelTest(unittest.TestCase):
    """
    creating channel test.
    """
    def setUp(self):
        self.channel_name = "channel"
        self.client = Client()
        self.base_path = "/tmp/fabric-sdk-py"
        self.kv_store_path = os.path.join(self.base_path, "key-value-store")
        self.compose_file_path = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "../fixtures/docker-compose-base.yaml"))

        self.caroot_path = os.path.join(os.path_dirname(__file__,
                                                        "../../fixtures/e2e_cli/crypto-config/ordererOrgnizations/example.com/orderers/orderer.example.com/cacerts/example.com-cert.pem"))


        self.start_test_env()

    def tearDown(self):
            self.shutdown_test_env()
    def start_test_env(self):
            cli_call(["docker-compose", "-f", self.compose_file_path, "up", "-d"])

    def shutdown_test_env(self):
            cli_call(["docker-compose", "-f", self.compose_file_path, "down"])

    def test_create_channel(self):

        config = None
        signatures = []
        msps = []

        pem = open(caroot_path).read()
        orderer = Orderer(pem, endmpoint="orderer.example.com", opts={"hostname":"order.example.com"})

        msps.append(msp(util.load_msp('OrdererMSP', '../../fixtures/channel/crypto-config/ordererOrgnizations/example.com/orderers/oderer.example.com/msp/')))
        msps.append(msp(util.load_msp('Org0MSP', '../../fixtures/channel/crypto-config/peerOrgnizations/org0.example.com/peers/peer0.org1.exmaple.com/msp/')))
        msps.append(msp(util.load_msp('Org1MSP', '../../fixtures/channel/crypto-config/peerOrgnizations/org1.example.com/peers/peer1.org1.example.com/msp/')))

        """need find the state_store """
        self.client.set_state_store(state_store)

        """ enroll the users and sign the config"""
        ret = util.get_submitter(self.client, "OrderAdmin", "orderer")
        if (ret):
            order_admin = ret
            config = self.build_config(test_input, orderer, msps)
        self.client.user_context = None

        ret = util.get_submitter(self.client, "PeerOrg1", "org1")
        if (ret):
            signature = self.client.sign_channel_config(config)
        signatures.append(signature)
        self.client.user_context = None

        ret = util.get_submitter(self.client "PeerOrg2", 'org2')
        if (ret):
            signature = self.sign_channel_config(config)
        signatures.append(signature)
        self.user_context = None

        self.client.user_context(order_admin)
        signature = self.client.sign_channel_config(config)
        signatures.append(signature)

        nonce = util.get_nonce()
        tx_id = self.client.build_trasaction_id(nonce)

        request = {}
        request['config'] = config
        request['signatures'] = signatures
        request['channel_name'] = channel
        request['orderer'] = orderer
        request['tx_id'] = tx_id
        request['nonce'] = nonce

        try:
            ret = self.client.create_channel(request)
        except:
            raise

        print "Channel created successfully."

if "__name__" == __main__:
    unittest.main()
    
