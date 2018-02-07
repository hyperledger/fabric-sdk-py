# SPDX-License-Identifier: Apache-2.0

import os
import subprocess
import unittest

from hfc.fabric.client import Client
from hfc.fabric.user import create_user
from test.integration.config import E2E_CONFIG
from hfc.util.keyvaluestore import FileKeyValueStore


class BaseTestCase(unittest.TestCase):
    """
    Base class for test cases.
    All test cases can feel free to implement this.
    """

    def setUp(self):
        self.gopath_bak = os.environ.get('GOPATH', '')
        gopath = os.path.normpath(os.path.join(os.path.dirname(__file__),
                                               "../fixtures/chaincode"))
        os.environ['GOPATH'] = os.path.abspath(gopath)
        self.channel_tx = \
            E2E_CONFIG['test-network']['channel-artifacts']['channel.tx']
        self.compose_file_path = \
            E2E_CONFIG['test-network']['docker']['compose_file_tls']

        self.base_path = "/tmp/fabric-sdk-py"
        self.kv_store_path = os.path.join(self.base_path, "key-value-store")
        self.client = Client(state_store=FileKeyValueStore(self.kv_store_path))

        self.channel_name = "businesschannel"  # default application channel
        self.start_test_env()

    def tearDown(self):
        self.shutdown_test_env()

    def start_test_env(self):
        cli_call(["docker-compose", "-f", self.compose_file_path, "up", "-d"])

    def shutdown_test_env(self):
        cli_call(["docker-compose", "-f", self.compose_file_path, "down"])


def get_peer_org_user(org, user, state_store):
    """Loads the requested user for a given peer org
        and returns a user object.
    """

    peer_user_base_path = os.path.join(
        os.getcwd(),
        'test/fixtures/e2e_cli/crypto-config/peerOrganizations/{0}'
        '/users/{1}@{0}/msp/'.format(org, user)
    )

    key_path = os.path.join(
        peer_user_base_path, 'keystore/',
        E2E_CONFIG['test-network'][org]['users'][user]['private_key']
    )

    cert_path = os.path.join(
        peer_user_base_path, 'signcerts/',
        E2E_CONFIG['test-network'][org]['users'][user]['cert']
    )

    msp_id = E2E_CONFIG['test-network'][org]['mspid']

    return create_user(user, org, state_store, msp_id, key_path, cert_path)


def get_orderer_org_user(org='example.com', user='Admin', state_store=None):
    """Loads the admin user for a given orderer org and
        returns an user object.
        Currently, orderer org only has Admin

    """
    msp_path = os.path.join(
        os.getcwd(),
        'test/fixtures/e2e_cli/crypto-config/ordererOrganizations/'
        'example.com/users/Admin@example.com/msp/')

    key_path = os.path.join(
        msp_path, 'keystore/',
        E2E_CONFIG['test-network']['orderer']['users'][user]['private_key']
    )

    cert_path = os.path.join(
        msp_path, 'signcerts',
        E2E_CONFIG['test-network']['orderer']['users'][user]['cert']
    )
    msp_id = E2E_CONFIG['test-network']['orderer']['mspid']

    return create_user(user, org, state_store, msp_id, key_path, cert_path)


def cli_call(arg_list, expect_success=True, env=os.environ.copy()):
    """Executes a CLI command in a subprocess and return the results.

    Args:
        arg_list: a list command arguments
        expect_success: use False to return even if an error occurred
                        when executing the command
        env:

    Returns: (string, string, int) output message, error message, return code

    """
    p = subprocess.Popen(arg_list, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=env)
    output, error = p.communicate()
    if p.returncode != 0:
        if output:
            print("Output:\n" + str(output))
        if error:
            print("Error Message:\n" + str(error))
        if expect_success:
            raise subprocess.CalledProcessError(
                p.returncode, arg_list, output)
    return output, error, p.returncode
