# Copyright IBM ALL Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
import asyncio
import logging
from hfc.fabric.peer import create_peer
from hfc.fabric.transaction.tx_context import create_tx_context
from hfc.fabric.transaction.tx_proposal_request import create_tx_prop_req, \
    CC_INVOKE, CC_TYPE_GOLANG, CC_INSTANTIATE, CC_INSTALL, TXProposalRequest
from hfc.util.crypto.crypto import ecies
from hfc.util.utils import build_tx_req, send_transaction
from test.integration.utils import get_peer_org_user, \
    BaseTestCase
from test.integration.config import E2E_CONFIG
from test.integration.e2e_utils import build_channel_request, \
    build_join_channel_req, get_stream_result

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
test_network = E2E_CONFIG['test-network']
CC_PATH = 'github.com/example_cc'
CC_NAME = 'example_cc'
CC_VERSION = '1.0'


class ChaincodeInvokeTest(BaseTestCase):

    def test_invoke_chaincode_sucess(self):
        loop = asyncio.get_event_loop()

        channel = self.client.new_channel(self.channel_name)
        org1 = "org1.example.com"
        peer_config = test_network['org1.example.com']['peers']['peer0']
        tls_cacerts = peer_config['tls_cacerts']
        opts = (('grpc.ssl_target_name_override',
                 peer_config['server_hostname']),)
        endpoint = peer_config['grpc_request_endpoint']
        org1_peer = create_peer(endpoint=endpoint,
                                tls_cacerts=tls_cacerts,
                                opts=opts)
        org1_admin = get_peer_org_user(org1,
                                       "Admin",
                                       self.client.state_store)

        crypto = ecies()
        tran_prop_req_install = create_tx_prop_req(
            prop_type=CC_INSTALL,
            cc_path=CC_PATH,
            cc_type=CC_TYPE_GOLANG,
            cc_name=CC_NAME,
            cc_version=CC_VERSION)
        tx_context_install = create_tx_context(
            org1_admin,
            crypto,
            tran_prop_req_install)

        args_dep = ['a', '200', 'b', '300']
        tran_prop_req_dep = create_tx_prop_req(
            prop_type=CC_INSTANTIATE,
            cc_type=CC_TYPE_GOLANG,
            cc_name=CC_NAME,
            cc_version=CC_VERSION,
            args=args_dep,
            fcn='init')

        tx_context_dep = create_tx_context(org1_admin,
                                           crypto,
                                           tran_prop_req_dep)

        args = ['a', 'b', '100']
        tran_prop_req = create_tx_prop_req(prop_type=CC_INVOKE,
                                           cc_type=CC_TYPE_GOLANG,
                                           cc_name=CC_NAME,
                                           fcn='invoke',
                                           args=args)
        tx_context = create_tx_context(org1_admin, crypto, tran_prop_req)

        request = build_channel_request(self.client,
                                        self.channel_tx,
                                        self.channel_name)
        loop.run_until_complete(self.client._create_or_update_channel(request))

        join_req = loop.run_until_complete(
            build_join_channel_req(org1, channel, self.client))
        responses = channel.join_channel(join_req)
        res = loop.run_until_complete(asyncio.gather(*responses))
        self.assertTrue(all([x.response.status == 200 for x in res]))

        responses, proposal, header = self.client.send_install_proposal(
            tx_context_install, [org1_peer])
        loop.run_until_complete(asyncio.gather(*responses))

        responses, proposal, header = channel.send_instantiate_proposal(
            tx_context_dep, [org1_peer])
        res = loop.run_until_complete(asyncio.gather(*responses))

        tran_req = build_tx_req((res, proposal, header))
        send_transaction(channel.orderers, tran_req, tx_context)
        loop.run_until_complete(get_stream_result(
            send_transaction(channel.orderers, tran_req, tx_context)))

        tx_context_tx = create_tx_context(org1_admin,
                                          crypto,
                                          TXProposalRequest())
        responses, proposal, header = channel.send_tx_proposal(tx_context,
                                                               [org1_peer])
        res = loop.run_until_complete(asyncio.gather(*responses))

        tran_req = build_tx_req((res, proposal, header))

        responses = loop.run_until_complete(get_stream_result(
            send_transaction(channel.orderers, tran_req, tx_context_tx)))

        self.assertTrue(all([x.status == 200 for x in responses]))
