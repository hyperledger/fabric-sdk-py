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
            'compose_file_raft': 'test/fixtures/e2e_raft/docker-compose-2orgs-4peers-tls.yaml',
            'compose_file_orderer_raft': 'test/fixtures/e2e_raft/docker-compose-etcdraft2.yaml',
        },
        'channel-artifacts': {
            'channel_id': 'businesschannel',
            'channel.tx': 'test/fixtures/e2e_cli/channel-artifacts/channel.tx',
            'config_yaml': 'test/fixtures/e2e_cli/',
            'channel_profile': 'TwoOrgsChannel',
            'raft_channel.tx': 'test/fixtures/e2e_raft/channel-artifacts/channel.tx',
            'raft_config_yaml': 'test/fixtures/e2e_raft',
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
                    'private_key': '5ba7f687f7c784a4a8af9251d6fb5cc91778535ab86b76a4576887f02668b230_sk'}
            }
        },
        'org1.example.com': {
            'mspid': 'Org1MSP',
            'users': {
                'Admin': {
                    'cert': 'Admin@org1.example.com-cert.pem',
                    'private_key': '5f017750c105c40314864c9231915983521b594060a5708e01046f6ce8d78460_sk'
                },
                'User1': {
                    'cert': 'User1@org1.example.com-cert.pem',
                    'private_key': 'e2eede666b16e7f6b8e5f0f8db622d419f637acaf69dbebc5d192e6acc3eeebd_sk'
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
                    'private_key': '13226122360317d743e85addf0d2af7affdf0a45b06dcef03c32998c90715bcf_sk'
                },
                'User1': {
                    'cert': 'User1@org2.example.com-cert.pem',
                    'private_key': '037a30e0dbb4de6e9dfe9861ebd13f2b015c16c9c172cd3be555c14fe9395a9b_sk'
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
