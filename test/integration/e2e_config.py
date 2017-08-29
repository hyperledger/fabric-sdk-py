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
# flake8: noqa
"""Contains the paths and attributes necessary for the integration tests."""
E2E_CONFIG = {
    'test-network': {
        'docker': {
            'compose_file_no_tls': 'test/fixtures/docker-compose-1peer-notls.yaml',
            'compose_file_tls': 'test/fixtures/docker-compose-base.yaml'
        },
        'channel-artifacts': {
            'channel_id': 'businesschannel',
            'channel.tx': 'test/fixtures/e2e_cli/channel-artifacts/channel.tx'
        },
        'orderer': {
            'grpc_endpoint': 'localhost:7050',
            'server_hostname': 'orderer.example.com',
            'tls_cacerts': 'test/fixtures/e2e_cli/crypto-config/ordererOrganizations/'
            'example.com/tlsca/tlsca.example.com-cert.pem',
            'mspid': 'OrdererMSP',
            'users': {
                'admin': {
                    'cert': 'Admin@example.com-cert.pem',
                    'private_key': 'b92d5923828aa15d965e438de5a7edb92ec128889c2fe8026ee7b95490270048_sk'}
            }
        },
        'org1.example.com': {
            'mspid': 'Org1MSP',
            'users': {
                'admin': {
                    'cert': 'Admin@org1.example.com-cert.pem',
                    'private_key': '570182787133a5137f0982ba0e018462d3ed20491402585741bb516922fc9416_sk'
                }
            }
        },
        'org2.example.com': {
            'mspid': 'Org2MSP',
            'users': {
                'admin': {
                    'cert': 'Admin@org2.example.com-cert.pem',
                    'private_key': 'a23db9fe4fdfc7d8f87a42919597b44e52b429fb09634b523b366146b9bf1e3b_sk'
                }
            }
        }
    }
}
