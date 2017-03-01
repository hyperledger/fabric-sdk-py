# -*- coding: utf-8 -*-

import os
import sys
import time
import unittest
# from shutil import rmtree

from hfc.api.ca.caservice import ca_service
from hfc.api.chain.installment import create_installment_proposal_req
from hfc.api.chain.instantiation import create_instantiation_proposal_req
from hfc.api.chain.invocation import create_invocation_proposal_req
from hfc.api.client import Client
from hfc.api.crypto.crypto import ecies
from hfc.api.msp.msp import msp
from hfc.api.peer import Peer
from hfc.api.user import User
from hfc.util.keyvaluestore import file_key_value_store
from test.unit.util import cli_call

if sys.version_info < (3, 0):
    from Queue import Queue
else:
    from queue import Queue

CHAINCODE_PATH = 'github.com/example_cc'
CHAINCODE_NAME = 'example_cc'
CHAINCODE_VERSION = 'v1'
CHAIN_ID = 'testchainid'

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
        self.base_path = '/tmp/fabric-sdk-py'
        self.kv_store_path = os.path.join(self.base_path, 'key-value-store')

    def tearDown(self):
        if self.gopath_bak:
            os.environ['GOPATH'] = self.gopath_bak
        # rmtree(self.base_path)

    @unittest.skip
    def test_install(self):
        start_test_env()
        time.sleep(5)
        client = Client()
        chain = client.new_chain(CHAIN_ID)
        client.set_state_store(file_key_value_store(self.kv_store_path))
        chain.add_peer(Peer())

        submitter = get_submitter()
        signing_identity = submitter.signing_identity
        cc_install_req = create_installment_proposal_req(
            CHAINCODE_NAME, CHAINCODE_PATH,
            CHAINCODE_VERSION, signing_identity)
        queue = Queue(1)

        chain.install_chaincode(cc_install_req) \
            .subscribe(lambda x: queue.put(x))

        prop = queue.get()
        print(prop)
        shutdown_test_env()

    @unittest.skip
    def test_instantiate(self):
        start_test_env()
        time.sleep(5)
        client = Client()
        chain = client.new_chain(CHAIN_ID)
        client.set_state_store(file_key_value_store(self.kv_store_path))
        chain.add_peer(Peer())

        submitter = get_submitter()
        signing_identity = submitter.signing_identity
        cc_instantiate_req = create_instantiation_proposal_req(
            CHAINCODE_NAME, CHAINCODE_PATH,
            CHAINCODE_VERSION, signing_identity,
            args=['a', '100', 'b', '200'])
        queue = Queue(1)

        chain.instantiate_chaincode(cc_instantiate_req) \
            .subscribe(lambda x: queue.put(x))

        prop = queue.get()
        proposal_bytes = prop.proposal_bytes
        sig = prop.signature

        # verify the signature against the hash of proposal_bytes
        digest = signing_identity.msp.crypto_suite.hash(proposal_bytes)
        self.assertEqual(
            signing_identity.verify(str.encode(digest.hexdigest()),
                                    sig),
            True)
        shutdown_test_env()

    @unittest.skip
    def test_invoke(self):
        start_test_env()
        time.sleep(5)
        client = Client()
        chain = client.new_chain(CHAIN_ID)
        client.set_state_store(file_key_value_store(self.kv_store_path))
        chain.add_peer(Peer())

        submitter = get_submitter()
        signing_identity = submitter.signing_identity
        cc_invoke_req = create_invocation_proposal_req(
            CHAINCODE_NAME, CHAINCODE_VERSION, signing_identity,
            args=['move', 'a', 'b', '100'])
        queue = Queue(1)

        chain.invoke_chaincode(cc_invoke_req) \
            .subscribe(lambda x: queue.put(x))

        prop = queue.get()
        proposal_bytes = prop.proposal_bytes
        sig = prop.signature

        # verify the signature against the hash of proposal_bytes
        digest = signing_identity.msp.crypto_suite.hash(proposal_bytes)
        self.assertEqual(
            signing_identity.verify(str.encode(digest.hexdigest()),
                                    sig),
            True)
        shutdown_test_env()


def get_submitter():
    ca = ca_service()
    user = User(USER_ID, USER_PASSWD, msp_impl=msp('DEFAULT', ecies()), ca=ca)
    user.enroll()

    return user


def shutdown_test_env():
    cli_call(["docker-compose", "-f",
              os.path.join(os.path.dirname(__file__),
                           "../fixtures/chaincode/docker-compose.yml"),
              "down"])


def start_test_env():
    cli_call(["docker-compose", "-f",
              os.path.join(os.path.dirname(__file__),
                           "../fixtures/chaincode/docker-compose.yml"),
              "up", "-d"])


if __name__ == '__main__':
    unittest.main()
