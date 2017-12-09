"""
# Copyright IBM Corp. 2017 All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
"""

from hfc.fabric.orderer import Orderer
from hfc.fabric.peer import Peer
from hfc.fabric.eventhub import EventHub
from hfc.fabric.transaction.tx_context import TXContext
from hfc.fabric.transaction.tx_proposal_request import TXProposalRequest
from hfc.util.crypto.crypto import ecies
from hfc.util import utils

from test.integration.utils import get_orderer_org_admin, get_peer_org_user

from test.integration.config import E2E_CONFIG
test_network = E2E_CONFIG['test-network']


def build_channel_request(client, channel_tx, channel_name):
    """
    Args:
        client: the client instance
        channel_tx: channel config file
        channel_name: channel name
    return channel request to create a channel
    """

    signatures = []
    prop_req = TXProposalRequest()
    with open(channel_tx, 'rb') as f:
        envelope = f.read()
        config = utils.extract_channel_config(envelope)

    orderer_config = E2E_CONFIG['test-network']['orderer']
    with open(orderer_config['tls_cacerts'], 'rb') as tls_cacerts:
        pem = tls_cacerts.read()

    opts = (('grpc.ssl_target_name_override', 'orderer.example.com'),)
    orderer = Orderer(
        endpoint=orderer_config['grpc_endpoint'],
        pem=pem,
        opts=opts
    )
    orderer_admin = get_orderer_org_admin(client)
    orderer_tx_context = TXContext(orderer_admin, ecies(), prop_req, {})
    client.tx_context = orderer_tx_context
    orderer_admin_signature = client.sign_channel_config(config)
    orderer_admin_signature_bytes = orderer_admin_signature.SerializeToString()
    signatures.append(orderer_admin_signature_bytes)
    tx_id = orderer_tx_context.tx_id
    nonce = orderer_tx_context.nonce

    org1_admin = get_peer_org_user(client, 'org1.example.com')
    org1_tx_context = TXContext(org1_admin, ecies(), prop_req, {})
    client.tx_context = org1_tx_context
    org1_admin_signature = client.sign_channel_config(config)
    org1_admin_signature_bytes = org1_admin_signature.SerializeToString()

    signatures.append(org1_admin_signature_bytes)

    org2_admin = get_peer_org_user(client, 'org2.example.com')
    org2_tx_context = TXContext(org2_admin, ecies(), prop_req, {})
    client.tx_context = org2_tx_context
    org2_admin_signature = client.sign_channel_config(config)
    org2_admin_signature_bytes = org2_admin_signature.SerializeToString()
    signatures.append(org2_admin_signature_bytes)

    request = {'config': config,
               'signatures': signatures,
               'channel_name': channel_name,
               'orderer': orderer,
               'tx_id': tx_id,
               'nonce': nonce}

    return request


def disconnect(all_ehs):
    """
    disconnect the eventhubs if connected
    Args:
        all_ehs: all the event hubs
    Return: no return value
    """
    for eh in all_ehs:
        if eh.is_connected:
            eh.disconnect()


def build_join_channel_req(org, channel, client):
    """
    For test, there is only one peer.

    Args:
        org: org
        channel: the channel to join
        client: client instance
    Return:
        return request for joining channel
        """

    def block_event_callback(block):

        pass

    client._crypto_suite = ecies()
    all_ehs = []
    request = {}
    tx_prop_req = TXProposalRequest()

    # add the orderer
    orderer_config = test_network['orderer']
    endpoint = orderer_config['grpc_endpoint']
    opts = (('grpc.ssl_target_name_override',
             orderer_config['server_hostname']),)

    ca_root_path = orderer_config['tls_cacerts']
    with open(ca_root_path, 'rb') as f:
        pem = f.read()
    orderer = Orderer(endpoint=endpoint, pem=pem, opts=opts)
    channel.add_orderer(orderer)

    # get the genesis block
    orderer_admin = get_orderer_org_admin(client)
    tx_context = TXContext(orderer_admin, ecies(), tx_prop_req)
    client.tx_context = tx_context
    genesis_block = channel.get_genesis_block().SerializeToString()
    if not genesis_block:
        return None

    # create the peer
    org_admin = get_peer_org_user(client, org)
    client.tx_context = TXContext(org_admin, ecies(), tx_prop_req)

    peer_config = test_network[org]["peers"]['peer0']
    ca_root = peer_config["tls_cacerts"]
    with open(ca_root, 'rb') as f:
        pem = f.read()
    peer = Peer(pem=pem, opts=None)

    # connect the peer
    eh = EventHub()
    event = peer_config['grpc_event_endpoint']
    opts = {'pem': pem, 'hostname': peer_config['server_hostname']}

    tx_id = client.tx_context.tx_id
    eh.set_peer_addr(event)
    eh.connect()
    eh.register_block_event(block_event_callback)
    all_ehs.append(eh)

    request["targets"] = [peer]
    request["block"] = genesis_block
    request["tx_id"] = tx_id

    return request
