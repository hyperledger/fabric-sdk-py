"""
# Copyright IBM Corp. 2017 All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
"""


from hfc.fabric.orderer import Orderer
from hfc.fabric.transaction.tx_context import TXContext
from hfc.fabric.transaction.tx_proposal_request import TXProposalRequest
from hfc.util.crypto.crypto import Ecies
from hfc.util import utils

from test.unit.util import get_orderer_org_admin, get_peer_org_admin

from test.integration.config import E2E_CONFIG


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
    orderer_tx_context = TXContext(orderer_admin, Ecies(), prop_req, {})
    client.tx_context = orderer_tx_context
    orderer_admin_signature = client.sign_channel_config(config)
    orderer_admin_signature_bytes = orderer_admin_signature.SerializeToString()
    signatures.append(orderer_admin_signature_bytes)
    tx_id = orderer_tx_context.tx_id
    nonce = orderer_tx_context.nonce

    org1_admin = get_peer_org_admin(client, 'org1.example.com')
    org1_tx_context = TXContext(org1_admin, Ecies(), prop_req, {})
    client.tx_context = org1_tx_context
    org1_admin_signature = client.sign_channel_config(config)
    org1_admin_signature_bytes = org1_admin_signature.SerializeToString()

    signatures.append(org1_admin_signature_bytes)

    org2_admin = get_peer_org_admin(client, 'org2.example.com')
    org2_tx_context = TXContext(org2_admin, Ecies(), prop_req, {})
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
