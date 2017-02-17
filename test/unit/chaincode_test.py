# -*- coding: utf-8 -*-

import os
import sys
import time
import unittest

from hfc.api.chain import ChaincodeDeploymentRequest,\
    _create_deployment_proposal
from hfc.api.client import Client
from hfc.api.peer import Peer
from hfc.api.user import User
from hfc.api.ca.caservice import CAService
from test.unit.util import cli_call

if sys.version_info < (3, 0):
    from Queue import Queue
else:
    from queue import Queue

CHAINCODE_PATH = 'github.com/example_cc'
CHAINCODE_NAME = 'example_cc'
FCN = 'init'
F_ARGS = ['a', '100', 'b', '200']
CHAIN_ID = 'TEST_CHAIN'
TX_ID = 'TEST_TRANS'

USER_ID = 'admin'
USER_PASSWD = 'adminpw'


class ChaincodeTest(unittest.TestCase):
    """ This is an example framework for test case
    """

    def setUp(self):
        self.gopath_bak = os.environ.get('GOPATH', '')
        gopath = os.path.join(os.path.dirname(__file__),
                              "../fixtures/chaincode")
        os.environ['GOPATH'] = os.path.abspath(gopath)

    def tearDown(self):
        if self.gopath_bak:
            os.environ['GOPATH'] = self.gopath_bak

    @staticmethod
    def start_test_env():
        cli_call(["docker-compose", "-f",
                  os.path.join(os.path.dirname(__file__),
                               "../fixtures/chaincode/docker-compose.yml"),
                  "up", "-d"])

    @staticmethod
    def shutdown_test_env():
        cli_call(["docker-compose", "-f",
                  os.path.join(os.path.dirname(__file__),
                               "../fixtures/chaincode/docker-compose.yml"),
                  "down"])

    @staticmethod
    def get_submitter():
        ca_server_address = os.getenv("CA_ADDR", 'localhost:7054')
        ca_service = CAService("http://" + ca_server_address)
        private_key, cert = ca_service.enroll(enrollment_id=USER_ID,
                                              enrollment_secret=USER_PASSWD)
        user = User(None)
        user.set_enrollment(private_key, cert)
        return user

    def test_sign_proposal(self):
        self.start_test_env()
        time.sleep(5)
        submitter = self.get_submitter()
        signing_identity = submitter.get_signing_identity()
        cc_deployment_req = \
            ChaincodeDeploymentRequest(CHAINCODE_PATH,
                                       CHAINCODE_NAME,
                                       FCN, CHAIN_ID, TX_ID,
                                       F_ARGS,
                                       signing_identity=signing_identity)
        signed_proposal = _create_deployment_proposal(cc_deployment_req)
        proposal_bytes = signed_proposal.proposal_bytes
        sig = signed_proposal.signature

        # verify the signature against the hash of proposal_bytes
        digest = signing_identity.msp.crypto_suite.hash(proposal_bytes)
        self.assertEqual(
            signing_identity.verify(str.encode(digest.hexdigest()),
                                    sig),
            True)
        self.shutdown_test_env()

    def test_deploy(self):
        self.start_test_env()
        time.sleep(5)
        grpc_addr = os.environ.get('GRPC_ADDR', 'localhost:7050')
        client = Client()
        chain = client.new_chain(CHAIN_ID)
        client.set_state_store('test_store')
        chain.add_peer(Peer(endpoint=grpc_addr))

        submitter = self.get_submitter()
        signing_identity = submitter.get_signing_identity()
        cc_deployment_req = \
            ChaincodeDeploymentRequest(CHAINCODE_PATH,
                                       CHAINCODE_NAME,
                                       FCN, CHAIN_ID, TX_ID,
                                       F_ARGS,
                                       signing_identity=signing_identity)
        queue = Queue(1)

        chain.send_deployment_proposal(cc_deployment_req) \
            .subscribe(lambda x: queue.put(x))

        self.assertIsNotNone(queue.get())
        self.shutdown_test_env()


if __name__ == '__main__':
    unittest.main()
