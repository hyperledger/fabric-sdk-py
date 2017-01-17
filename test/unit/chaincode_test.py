# -*- coding: utf-8 -*-

import os
import time
import unittest

from hfc.api.client import Client
from hfc.api.peer import Peer
from test.unit.util import cli_call


CHAINCODE_PATH = 'github.com/example_cc'
CHAINCODE_NAME = 'example_cc'
FCN = 'init'
F_ARGS = ['a', '100', 'b', '200']
CHAIN_ID = 'TEST_CHAIN'
TX_ID = 'TEST_TRANS'


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

    def test_deploy(self):
        self.start_test_env()
        time.sleep(5)
        grpc_addr = os.environ.get('GRPC_ADDR', 'localhost:7050')
        client = Client()
        chain = client.new_chain(CHAIN_ID)
        client.set_kv_store('test_store')
        chain.add_peer(Peer(grpc_addr=grpc_addr))
        proposal = chain.create_deploy_proposal(chaincode_path=CHAINCODE_PATH,
                                                chaincode_name=CHAINCODE_NAME,
                                                fcn=FCN, args=F_ARGS,
                                                chain_id=CHAIN_ID, tx_id=TX_ID)
        self.assertIsNotNone(proposal)
        self.shutdown_test_env()


if __name__ == '__main__':
    unittest.main()
