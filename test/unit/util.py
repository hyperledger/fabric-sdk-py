# Copyright 2009-2017 SAP SE or an SAP affiliate company.
# All Rights Reserved.
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
import subprocess
from test.integration.config import E2E_CONFIG
from hfc.fabric.user import User
from hfc.fabric_ca.caservice import Enrollment
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend


def get_peer_org_admin(client, peer_org):
    """Loads the admin user for a given peer org
        and returns a user object.

    """

    peer_admin_base_path = os.path.join(
        os.getcwd(),
        'test/fixtures/e2e_cli/crypto-config/peerOrganizations/{0}'
        '/users/Admin@{0}/msp/'.format(peer_org)
    )

    key_path = os.path.join(
        peer_admin_base_path,
        'keystore/',
        E2E_CONFIG['test-network'][peer_org]['users']['admin']['private_key']
    )

    cert_path = os.path.join(
        peer_admin_base_path,
        'signcerts/',
        E2E_CONFIG['test-network'][peer_org]['users']['admin']['cert']
    )

    with open(key_path, 'rb') as key:
        key_pem = key.read()

    with open(cert_path, 'rb') as cert:
        cert_pem = cert.read()

    org_admin = User('peer' + peer_org + 'Admin',
                     peer_org, client.state_store)

    # wrap the key in a 'cryptography' private key object
    # so that all the methods can be used
    private_key = load_pem_private_key(key_pem, None, default_backend())

    enrollment = Enrollment(private_key, cert_pem)

    org_admin.enrollment = enrollment
    org_admin.msp_id = E2E_CONFIG['test-network'][peer_org]['mspid']

    return org_admin


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

    orderer_admin = User('ordererexample.comAdmin',
                         'example.com', client.state_store)

    private_key = load_pem_private_key(key_pem, None, default_backend())

    enrollment = Enrollment(private_key, cert_pem)

    orderer_admin.enrollment = enrollment
    orderer_admin.msp_id = E2E_CONFIG['test-network']['orderer']['mspid']

    return orderer_admin


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
