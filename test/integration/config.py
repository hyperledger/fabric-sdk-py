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
            'compose_file_tls': 'test/fixtures/docker-compose-2orgs-4peers-tls.yaml',
            'compose_file_tls_cli': 'test/fixtures/docker-compose-2orgs-4peers-tls-cli.yaml',
            'compose_file_mutual_tls': 'test/fixtures/docker-compose-2orgs-4peers-mutual-tls.yaml',
        },
        'channel-artifacts': {
            'channel_id': 'businesschannel',
            'channel.tx': 'test/fixtures/e2e_cli/channel-artifacts/channel.tx',
            'config_yaml': 'test/fixtures/e2e_cli/',
            'channel_profile': 'TwoOrgsChannel'
        },
        'orderer': {
            'grpc_endpoint': 'localhost:7050',
            'server_hostname': 'orderer.example.com',
            'tls_cacerts': 'test/fixtures/e2e_cli/crypto-config/ordererOrganizations/'
                           'example.com/tlsca/tlsca.example.com-cert.pem',
            'mspid': 'OrdererMSP',
            'users': {
                'Admin': {
                    'cert': 'Admin@example.com-cert.pem',
                    'private_key': '630e3767a6e1d3c8e646460123d397455103a900efb4d6fb679a9d9c481841fc_sk'}
            }
        },
        'org1.example.com': {
            'mspid': 'Org1MSP',
            'users': {
                'Admin': {
                    'cert': 'Admin@org1.example.com-cert.pem',
                    'private_key': 'c76527489d5820bd04da80a84c07033ca574413f80614091e04f05c276fb6896_sk'
                },
                'User1': {
                    'cert': 'User1@org1.example.com-cert.pem',
                    'private_key': 'da72fd6c0f4595d33eb9ae6f6d06cd171ebc3882fc856960c244b9b5c2b35a90_sk'
                }
            },
            'peers': {
                'peer0': {
                    'grpc_request_endpoint': 'localhost:7051',
                    'grpc_event_endpoint': 'localhost:7053',
                    'server_hostname': 'peer0.org1.example.com',
                    'tls_cacerts': 'test/fixtures/e2e_cli/crypto-config/peerOrganizations/'
                                   'org1.example.com/peers/peer0.org1.example.com/msp/tlscacerts/'
                                   'tlsca.org1.example.com-cert.pem'
                }
            }
        },
        'org2.example.com': {
            'mspid': 'Org2MSP',
            'users': {
                'Admin': {
                    'cert': 'Admin@org2.example.com-cert.pem',
                    'private_key': '7e0b1c172161fe0f33603106935d2584918e12af955108e429dd63d4c043067a_sk'
                },
                'User1': {
                    'cert': 'User1@org2.example.com-cert.pem',
                    'private_key': '73beefad9003c589064deb2128c4f0831ba8003f1233102cc52a188afd05fe61_sk'
                }
            },
            'peers': {
                'peer0': {
                    'grpc_request_endpoint': 'localhost:9051',
                    'grpc_event_endpoint': 'localhost:9053',
                    'server_hostname': 'peer0.org2.example.com',
                    'tls_cacerts': 'test/fixtures/e2e_cli/crypto-config/peerOrganizations/'
                                   'org2.example.com/peers/peer0.org2.example.com/msp/tlscacerts/'
                                   'tlsca.org2.example.com-cert.pem'
                }
            }
        }
    }
}
