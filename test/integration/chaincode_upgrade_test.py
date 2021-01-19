# SPDX-License-Identifier: Apache-2.0
import asyncio
import logging

from hfc.util.policies import s2d

from hfc.fabric.chaincode import Chaincode
from test.integration.utils import get_peer_org_user, BaseTestCase
from test.integration.config import E2E_CONFIG

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
test_network = E2E_CONFIG['test-network']
CC_PATH = 'github.com/example_cc'
CC_NAME = 'example_cc'
CC_VERSION = '1.0'
CC_UPGRADED_VERSION = '1.1'


class ChaincodeUpgradeTest(BaseTestCase):
    async def upgrade_chaincode(self):
        org = 'org1.example.com'

        org_admin = get_peer_org_user(org, 'Admin', self.client.state_store)
        peers = ['peer0.' + org, 'peer1.' + org]

        # create a channel
        response = await self.client.channel_create(
            'orderer.example.com',
            self.channel_name,
            org_admin,
            config_yaml=self.config_yaml,
            channel_profile=self.channel_profile)
        self.assertTrue(response)

        # join channel
        response = await self.client.channel_join(
            requestor=org_admin,
            channel_name=self.channel_name,
            peers=['peer0.' + org, 'peer1.' + org],
            orderer='orderer.example.com'
        )
        self.assertTrue(response)

        instantiate_args = ['a', '200', 'b', '300']
        query_args = ['b']
        policy = s2d().parse("OR('Org1MSP.member')")

        chaincode = Chaincode(self.client, CC_NAME)
        res = await chaincode.install(org_admin, peers, CC_PATH, CC_VERSION)
        self.assertTrue(res)
        res = await chaincode.instantiate(org_admin, self.channel_name, peers, CC_VERSION, policy,
                                          args=instantiate_args, wait_for_event=True)
        self.assertTrue(res)
        res = await chaincode.query(org_admin, self.channel_name, peers, query_args)
        self.assertEqual(res, '300')
        res = await chaincode.install(org_admin, peers, CC_PATH, CC_UPGRADED_VERSION)
        self.assertTrue(res)
        res = await chaincode.upgrade(org_admin, self.channel_name, peers, CC_UPGRADED_VERSION, policy,
                                      args=instantiate_args, wait_for_event=True)
        self.assertTrue(res)
        res = await chaincode.query(org_admin, self.channel_name, peers, query_args)
        self.assertEqual(res, '300')

    def test_upgrade_chaincode(self):
        loop = asyncio.get_event_loop()

        loop.run_until_complete(self.upgrade_chaincode())
