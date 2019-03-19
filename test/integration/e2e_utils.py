"""
# Copyright IBM Corp. 2017 All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
"""

import logging
from hfc.fabric.orderer import Orderer
from hfc.fabric.transaction.tx_context import TXContext
from hfc.fabric.transaction.tx_proposal_request import TXProposalRequest
from hfc.util.crypto.crypto import ecies
from hfc.util import utils
from test.integration.utils import get_orderer_org_user, get_peer_org_user
from test.integration.config import E2E_CONFIG
test_network = E2E_CONFIG['test-network']

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


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
        tls_ca_cert_file=orderer_config['tls_cacerts'],
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


# This should be deprecated, the code should be included into the client's
# channel_join method
async def build_join_channel_req(org, channel, client):
    """
    For test, there is only one peer.

    Args:
        org: org
        channel: the channel to join
        client: client instance
    Return:
        return request for joining channel
        """

    tx_prop_req = TXProposalRequest()

    # add the orderer
    orderer = client.get_orderer('orderer.example.com')
    channel.add_orderer(orderer)

    # get the genesis block
    orderer_admin = client.get_user('orderer.example.com', 'Admin')
    tx_context = TXContext(orderer_admin, orderer_admin.cryptoSuite,
                           tx_prop_req)

    genesis_block = None
    stream = orderer.get_genesis_block(tx_context, channel.name)
    async for v in stream:
        if v.block is None or v.block == '':
            msg = "fail to get genesis block"
            raise Exception(msg)
        genesis_block = v.block
        break

    genesis_block = genesis_block.SerializeToString()

    org_admin = client.get_user(org, 'Admin')
    tx_context = TXContext(org_admin, org_admin.cryptoSuite, tx_prop_req)

    peer = client.get_peer('peer0.' + org)

    request = {
        "targets": [peer],
        "block": genesis_block,
        "tx_context": tx_context,
        "transient_map": {},
    }

    return request


async def get_stream_result(stream):
    res = []
    async for v in stream:
        logger.debug('Responses of send_transaction:\n {}'.format(v))
        res.append(v)
    return res
