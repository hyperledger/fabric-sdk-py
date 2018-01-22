"""
# Copyright IBM Corp. 2017 All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
"""

from hfc.fabric.orderer import Orderer
from hfc.fabric.peer import Peer
from hfc.fabric.transaction.tx_context import TXContext
from hfc.fabric.transaction.tx_proposal_request import TXProposalRequest
from hfc.util.crypto.crypto import ecies
from hfc.util import utils

from test.integration.utils import get_orderer_org_user, get_peer_org_user

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

    orderer = Orderer(
        endpoint=orderer_config['grpc_endpoint'],
        tls_cacerts=orderer_config['tls_cacerts'],
        opts=(('grpc.ssl_target_name_override',
               'orderer.example.com'),),
    )
    orderer_admin = get_orderer_org_user(state_store=client.state_store)
    orderer_tx_context = TXContext(orderer_admin, ecies(), prop_req, {})
    client.tx_context = orderer_tx_context
    orderer_admin_signature = client.sign_channel_config(config)
    signatures.append(orderer_admin_signature)
    tx_id = orderer_tx_context.tx_id
    nonce = orderer_tx_context.nonce

    org1_admin = get_peer_org_user('org1.example.com', "Admin",
                                   client.state_store)
    org1_tx_context = TXContext(org1_admin, ecies(), prop_req, {})
    client.tx_context = org1_tx_context
    org1_admin_signature = client.sign_channel_config(config)
    signatures.append(org1_admin_signature)

    org2_admin = get_peer_org_user('org2.example.com', "Admin",
                                   client.state_store)
    org2_tx_context = TXContext(org2_admin, ecies(), prop_req, {})
    client.tx_context = org2_tx_context
    org2_admin_signature = client.sign_channel_config(config)
    signatures.append(org2_admin_signature)

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
    request = {}
    tx_prop_req = TXProposalRequest()

    # add the orderer
    orderer_config = test_network['orderer']
    endpoint = orderer_config['grpc_endpoint']
    ca_root_path = orderer_config['tls_cacerts']
    orderer = Orderer(endpoint=endpoint, tls_cacerts=ca_root_path,
                      opts=(('grpc.ssl_target_name_override',
                             'orderer.example.com'),))
    channel.add_orderer(orderer)

    # get the genesis block
    orderer_admin = get_orderer_org_user(state_store=client.state_store)
    tx_context = TXContext(orderer_admin, ecies(), tx_prop_req)
    client.tx_context = tx_context
    genesis_block = channel.get_genesis_block().SerializeToString()

    # create the peer
    org_admin = get_peer_org_user(org, "Admin", client.state_store)
    client.tx_context = TXContext(org_admin, ecies(), tx_prop_req)
    tx_id = client.tx_context.tx_id

    peer_config = test_network[org]["peers"]['peer0']
    ca_root = peer_config["tls_cacerts"]

    endpoint = peer_config["grpc_request_endpoint"]
    opts = (('grpc.ssl_target_name_override',
             peer_config['server_hostname']),)
    peer = Peer(endpoint=endpoint, tls_cacerts=ca_root, opts=opts)

    """
    # connect the peer
    eh = EventHub()
    event = peer_config['grpc_event_endpoint']

    tx_id = client.tx_context.tx_id
    eh.set_peer_addr(event)
    eh.connect()
    eh.register_block_event(block_event_callback)
    all_ehs.append(eh)
    """

    request["targets"] = [peer]
    request["block"] = genesis_block
    request["tx_id"] = tx_id
    request["transient_map"] = {}

    return request
