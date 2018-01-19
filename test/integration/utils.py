# SPDX-License-Identifier: Apache-2.0

import os
import subprocess
import unittest

from hfc.fabric.client import Client
from test.integration.config import E2E_CONFIG
from hfc.fabric.user import User
from hfc.fabric_ca.caservice import Enrollment
from hfc.util.keyvaluestore import FileKeyValueStore
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend


class BaseTestCase(unittest.TestCase):
    """
    Base class for test cases.
    All test cases can feel free to implement this.
    """

    def setUp(self):
        self.gopath_bak = os.environ.get('GOPATH', '')
        gopath = os.path.normpath(os.path.join(os.path.dirname(__file__),
                                               "../../fixtures/chaincode"))
        os.environ['GOPATH'] = os.path.abspath(gopath)
        self.configtx_path = \
            E2E_CONFIG['test-network']['channel-artifacts']['channel.tx']
        self.compose_file_path = \
            E2E_CONFIG['test-network']['docker']['compose_file_tls']
        self.base_path = "/tmp/fabric-sdk-py"
        self.client = Client()
        self.kv_store_path = os.path.join(self.base_path, "key-value-store")
        self.client.state_store = FileKeyValueStore(self.kv_store_path)
        self.channel_name = "businesschannel"  # default application channel
        self.start_test_env()

    def tearDown(self):
        self.shutdown_test_env()

    def start_test_env(self):
        cli_call(["docker-compose", "-f", self.compose_file_path, "up", "-d"])

    def shutdown_test_env(self):
        cli_call(["docker-compose", "-f", self.compose_file_path, "down"])


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


def get_peer_org_user(client, peer_org, user='Admin'):
    """Loads the requested user for a given peer org
        and returns a user object.
    """

    peer_user_base_path = os.path.join(
        os.getcwd(),
        'test/fixtures/e2e_cli/crypto-config/peerOrganizations/{0}'
        '/users/{1}@{0}/msp/'.format(peer_org, user)
    )

    key_path = os.path.join(
        peer_user_base_path,
        'keystore/',
        E2E_CONFIG['test-network'][peer_org]['users'][user]['private_key']
    )

    cert_path = os.path.join(
        peer_user_base_path,
        'signcerts/',
        E2E_CONFIG['test-network'][peer_org]['users'][user]['cert']
    )

    with open(key_path, 'rb') as key:
        key_pem = key.read()

    with open(cert_path, 'rb') as cert:
        cert_pem = cert.read()

    org_user = User('peer' + peer_org + user, peer_org, client.state_store)

    # wrap the key in a 'cryptography' private key object
    # so that all the methods can be used
    private_key = load_pem_private_key(key_pem, None, default_backend())

    enrollment = Enrollment(private_key, cert_pem)

    org_user.enrollment = enrollment
    org_user.msp_id = E2E_CONFIG['test-network'][peer_org]['mspid']

    return org_user


def get_orderer_org_admin(client):
    """Loads the admin user for a given orderer org and
        returns an user object.

    """
    orderer_admin_base_path = os.path.join(
        os.getcwd(),
        'test/fixtures/e2e_cli/crypto-config/ordererOrganizations/'
        'example.com/users/Admin@example.com/msp/')

    key_path = os.path.join(
        orderer_admin_base_path,
        'keystore/',
        E2E_CONFIG['test-network']['orderer']['users']['admin']['private_key']
    )

    cert_path = os.path.join(
        orderer_admin_base_path, 'signcerts',
        E2E_CONFIG['test-network']['orderer']['users']['admin']['cert']
    )

    with open(key_path, 'rb') as key:
        key_pem = key.read()

    with open(cert_path, 'rb') as cert:
        cert_pem = cert.read()

    orderer_admin = User('ordererAdmin',
                         'example.com', client.state_store)

    private_key = load_pem_private_key(key_pem, None, default_backend())

    enrollment = Enrollment(private_key, cert_pem)

    orderer_admin.enrollment = enrollment
    orderer_admin.msp_id = E2E_CONFIG['test-network']['orderer']['mspid']

    return orderer_admin
