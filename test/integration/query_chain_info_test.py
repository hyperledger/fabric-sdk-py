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
from test.integration.utils import BaseTestCase, get_peer_org_user
from test.integration.config import E2E_CONFIG
from test.integration.e2e_utils import build_channel_request, \
    build_join_channel_req, get_stream_result

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
test_network = E2E_CONFIG['test-network']
CC_PATH = 'github.com/example_cc_with_event'
CC_NAME = 'example_cc_with_event'
CC_VERSION = '1.0'


class QueryChainInfoTest(BaseTestCase):

    async def invoke_chaincode(self):

        org1 = "org1.example.com"
        peer_config = test_network['org1.example.com']['peers']['peer0']
        tls_cacerts = peer_config['tls_cacerts']
        opts = (('grpc.ssl_target_name_override',
                 peer_config['server_hostname']),)
        endpoint = peer_config['grpc_request_endpoint']

        self.peer = create_peer(endpoint=endpoint,
                                tls_cacerts=tls_cacerts,
                                opts=opts)

        self.org1_admin = get_peer_org_user(org1,
                                            "Admin",
                                            self.client.state_store)

        # channel create
        request = build_channel_request(self.client,
                                        self.channel_tx,
                                        self.channel_name)
        responses = await self.client._create_or_update_channel(request)
        self.assertTrue(all([x.status == 200 for x in responses]))

        self.channel = self.client.new_channel(self.channel_name)

        # join channel

        join_req = await build_join_channel_req(org1, self.channel,
                                                self.client)

        responses = self.channel.join_channel(join_req)
        res = await asyncio.gather(*responses)
        self.assertTrue(all([x.response.status == 200 for x in res]))

        # install

        tran_prop_req_install = create_tx_prop_req(
            prop_type=CC_INSTALL,
            cc_path=CC_PATH,
            cc_type=CC_TYPE_GOLANG,
            cc_name=CC_NAME,
            cc_version=CC_VERSION)

        tx_context_install = create_tx_context(
            self.org1_admin,
            self.org1_admin.cryptoSuite,
            tran_prop_req_install)

        responses, proposal, header = self.client.send_install_proposal(
            tx_context_install, [self.peer])
        await asyncio.gather(*responses)

        # instantiate

        args_dep = ['a', '200', 'b', '300']

        tran_prop_req_dep = create_tx_prop_req(
            prop_type=CC_INSTANTIATE,
            cc_type=CC_TYPE_GOLANG,
            cc_name=CC_NAME,
            cc_version=CC_VERSION,
            args=args_dep,
            fcn='init')
        tx_context_dep = create_tx_context(self.org1_admin,
                                           self.org1_admin.cryptoSuite,
                                           tran_prop_req_dep)
        responses, proposal, header = self.channel.send_instantiate_proposal(
            tx_context_dep, [self.peer])
        res = await asyncio.gather(*responses)

        tran_req = build_tx_req((res, proposal, header))
        tx_context = create_tx_context(self.org1_admin,
                                       self.org1_admin.cryptoSuite,
                                       TXProposalRequest())
        await get_stream_result(
            send_transaction(self.client.orderers, tran_req, tx_context))

        # wait for event instantiate
        channel_event_hub = self.channel.newChannelEventHub(self.peer,
                                                            self.org1_admin)
        stream = channel_event_hub.connect(filtered=False)

        channel_event_hub.registerTxEvent(tx_context_dep.tx_id)

        try:
            await asyncio.wait_for(stream, timeout=30)
        except asyncio.TimeoutError:
            raise TimeoutError('waitForEvent timed out.')
        except Exception:
            raise
        finally:
            channel_event_hub.disconnect()

        # invoke part
        args = ['a', 'b', '100']
        tran_prop_req = create_tx_prop_req(prop_type=CC_INVOKE,
                                           cc_type=CC_TYPE_GOLANG,
                                           cc_name=CC_NAME,
                                           fcn='invoke',
                                           args=args)

        tx_context = create_tx_context(
            self.org1_admin,
            self.org1_admin.cryptoSuite,
            tran_prop_req
        )

        responses, p, h = self.channel.send_tx_proposal(tx_context,
                                                        [self.peer])
        res = await asyncio.gather(*responses)
        tran_req = build_tx_req((res, p, h))

        tx_context_tx = create_tx_context(self.org1_admin,
                                          self.org1_admin.cryptoSuite,
                                          tran_req)
        res = await get_stream_result(
            send_transaction(self.channel.orderers, tran_req, tx_context_tx))

        # wait for chaincode events
        channel_event_hub = self.channel.newChannelEventHub(self.peer,
                                                            self.org1_admin)

        stream = channel_event_hub.connect(filtered=False)

        self.blocks = []

        def onEvent(block):
            self.blocks.append(block)

        # channel_event_hub.registerTxEvent(tx_context.tx_id, onEvent)
        channel_event_hub.registerChaincodeEvent(CC_NAME, '^invoked*', onEvent)

        try:
            await asyncio.wait_for(stream, timeout=30)
        except asyncio.TimeoutError:
            raise TimeoutError('waitForEvent timed out.')
        except Exception:
            raise
        finally:
            channel_event_hub.disconnect()

        return self.blocks

    def test_query_chain_info(self):
        loop = asyncio.get_event_loop()

        loop.run_until_complete(self.invoke_chaincode())

        tx_context = create_tx_context(self.org1_admin,
                                       ecies(),
                                       TXProposalRequest())
        responses, proposal, header = self.channel.query_info(tx_context,
                                                              [self.peer])
        res = loop.run_until_complete(asyncio.gather(*responses))

        self.assertEqual(res[0].response.status, 200)
