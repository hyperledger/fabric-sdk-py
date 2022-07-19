# SPDX-License-Identifier: Apache-2.0

import asyncio
import json
import os
import tempfile
import time

import docker
import logging
import unittest

from hfc.fabric.chaincode import ChaincodeExecutionError, Chaincode
from hfc.fabric.lifecycle import Lifecycle
from hfc.fabric.client import Client
from test.integration.config import E2E_CONFIG
from test.integration.utils import BaseTestCase

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

CC_PATH = 'github.com/example_cc_go_mod'
CC_NAME = 'example_cc'
CC_VERSION = '1.0'
SYSTEM_CHANNEL_NAME = "byfn-sys-channel"


class LifecycleTests(BaseTestCase):

    def setUp(self):
        self.gopath_bak = os.environ.get('GOPATH', '')
        gopath = os.path.normpath(os.path.join(os.path.dirname(__file__),
                                               "../fixtures/chaincode"))
        os.environ['GOPATH'] = os.path.abspath(gopath)
        self.compose_file_path = \
            E2E_CONFIG['test-network']['docker']['compose_file_2_0']

        self.config_yaml = \
            E2E_CONFIG['test-network']['channel-artifacts']['2_0_config_yaml']
        self.channel_profile = \
            E2E_CONFIG['test-network']['channel-artifacts']['channel_profile']
        self.client = Client('test/fixtures/network_2_0.json')

        with open('test/fixtures/network_2_0.json') as f:
            self.network_info = json.load(f)

        self.channel_name = "businesschannel"  # default application channel
        self.user = self.client.get_user('org1.example.com', 'Admin')
        self.package_id = ""
        self.assertIsNotNone(self.user, 'org1 admin should not be None')

        # Boot up the testing network
        self.shutdown_test_env()
        self.start_test_env()
        time.sleep(2)

    def tearDown(self):
        super(LifecycleTests, self).tearDown()

    async def channel_create(self):
        """
        Create an channel for further testing.

        :return:
        """
        logger.info(f"E2E: Channel creation start: name={self.channel_name}")

        # By default, self.user is the admin of org1
        response = await self.client.channel_create(
            'orderer.example.com',
            self.channel_name,
            self.user,
            config_yaml=self.config_yaml,
            channel_profile=self.channel_profile)
        self.assertTrue(response)
        time.sleep(2)
        logger.info(f"E2E: Channel creation done: name={self.channel_name}")

    async def channel_join(self):
        """
        Join peers of two orgs into an existing channels

        :return:
        """

        logger.info(f"E2E: Channel join start: name={self.channel_name}")

        # channel must already exist when to join
        channel = self.client.get_channel(self.channel_name)
        self.assertIsNotNone(channel)

        orgs = ["org1.example.com", "org2.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, 'Admin')
            response = await self.client.channel_join(
                requestor=org_admin,
                channel_name=self.channel_name,
                peers=['peer0.' + org, 'peer1.' + org],
                orderer='orderer.example.com'
            )
            self.assertTrue(response)
            # Verify the ledger exists now in the peer node
            dc = docker.from_env()
            for peer in ['peer0', 'peer1']:
                peer0_container = dc.containers.get(peer + '.' + org)
                code, output = peer0_container.exec_run(
                    'test -f '
                    '/var/hyperledger/production/ledgersData/chains/'
                    f'chains/{self.channel_name}'
                    '/blockfile_000000')
                self.assertEqual(code, 0, "Local ledger not exists")

        logger.info(f"E2E: Channel join done: name={self.channel_name}")

    async def chaincode_package(self):
        """
        Test packaging of the chaincode
        """
        logger.info("E2E: Chaincode package start")
        with tempfile.NamedTemporaryFile(mode="w+b") as tar:
            lifecycle = Lifecycle(self.client, CC_NAME)
            code = lifecycle.package(CC_PATH, CC_NAME, tar.name)
            self.assertTrue(code)
            self.assertEqual(code, tar.read())
        logger.info("E2E: Chaincode package done")

    async def chaincode_install(self):
        """
        Test installing an example chaincode to peer
        """
        logger.info("E2E: Chaincode install start")
        lifecycle = Lifecycle(self.client, CC_NAME)
        tar = lifecycle.package(CC_PATH, CC_NAME)
        self.assertTrue(tar)
        orgs = ["org1.example.com", "org2.example.com"]
        for org in orgs:

            # simulate possible different chaincode archive based on timestamp
            time.sleep(2)
            org_admin = self.client.get_user(org, "Admin")
            res = await lifecycle.install(org_admin, ['peer0.' + org, 'peer1.' + org], packaged_cc=tar)
            self.assertTrue(res)
            self.assertTrue(res[0]["packageId"])
            self.package_id = res[0]["packageId"]

        logger.info("E2E: chaincode install done")

    async def chaincode_approve_for_my_org(self):
        """
        Test approve chaincode definition for orgs
        """
        logger.info("E2E: Approve chaincode definition start")
        lifecycle = Lifecycle(self.client, CC_NAME)

        policy = "OR('Org1MSP.member')"

        orgs = ["org1.example.com", "org2.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            await lifecycle.approve_for_my_org(org_admin, ['peer0.' + org, 'peer1.' + org], self.channel_name,
                                               CC_VERSION, self.package_id, policy, wait_for_event=True,
                                               init_required=True)
        logger.info("E2E: Approve chaincode definition done")

    async def commit_chaincode_def(self):
        """
        Test commit chaincode definition to channel
        """
        logger.info("E2E: Commit chaincode definition start")
        lifecycle = Lifecycle(self.client, CC_NAME)

        org = "org1.example.com"
        policy = "OR('Org1MSP.member')"

        org_admin = self.client.get_user(org, "Admin")
        await lifecycle.commit_definition(org_admin, ['peer0.' + org, 'peer1.' + org], self.channel_name, CC_VERSION,
                                          policy, wait_for_event=True, init_required=True)
        time.sleep(2)
        logger.info("E2E: Commit chaincode definition done")

    async def initialize_chaincode(self):
        """
       Test initialising chaincode
       """
        logger.info("E2E: Chaincode initialisation start")
        chaincode = Chaincode(self.client, CC_NAME)
        org = "org1.example.com"
        org_admin = self.client.get_user(org, "Admin")
        args = ['a', '200', 'b', '300']
        res = await chaincode.invoke(org_admin, self.channel_name, ['peer0.' + org, 'peer1.' + org], args, fcn="Init",
                                     is_init=True, wait_for_event=True)
        self.assertEqual("", res, res)
        time.sleep(2)
        logger.info("E2E: Chaincode initialisation done")

    async def chaincode_invoke(self):
        """
        Test invoking an example chaincode to peer

        :return:
        """
        logger.info("E2E: Chaincode invoke start")

        orgs = ["org1.example.com"]
        args = ['a', 'b', '100']
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")

            response = await self.client.chaincode_invoke(
                requestor=org_admin,
                channel_name=self.channel_name,
                peers=['peer1.' + org],
                args=args,
                cc_name=CC_NAME,
                wait_for_event=True
            )
            self.assertEqual(response, '400')  # 300 + 100

        logger.info("E2E: chaincode invoke done")

    async def chaincode_invoke_fail(self):
        """
        Test invoking an example chaincode to peer

        :return:
        """
        logger.info("E2E: Chaincode invoke fail start")

        orgs = ["org2.example.com"]
        args = ['a', 'b', '100']
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            with self.assertRaises(Exception) as e:
                await self.client.chaincode_invoke(
                    requestor=org_admin,
                    channel_name=self.channel_name,
                    peers=['peer1.' + org],
                    args=args,
                    cc_name=CC_NAME,
                    wait_for_event=True
                )
            self.assertEqual(e.exception.args[0],
                             ['ENDORSEMENT_POLICY_FAILURE'])

        logger.info("E2E: chaincode invoke fail done")

    async def chaincode_invoke_fail_proposal(self):
        """
        Test invoking an example chaincode to peer

        :return:
        """
        logger.info("E2E: Chaincode invoke failed proposal start")

        orgs = ["org1.example.com"]
        args = ['a', '100']
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            with self.assertRaises(ChaincodeExecutionError):
                await self.client.chaincode_invoke(
                    requestor=org_admin,
                    channel_name=self.channel_name,
                    peers=['peer1.' + org],
                    args=args,
                    cc_name=CC_NAME,
                    wait_for_event=True,
                    raise_on_error=True
                )

        logger.info("E2E: chaincode invoke failed proposal done")

    async def chaincode_query(self, orgs=None):
        """
        Test invoking an example chaincode to peer

        :return:
        """
        logger.info("E2E: Chaincode query start")

        if orgs is None:
            orgs = ["org1.example.com"]

        args = ['b']
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            response = await self.client.chaincode_query(
                requestor=org_admin,
                channel_name=self.channel_name,
                peers=['peer0.' + org],
                args=args,
                cc_name=CC_NAME
            )
            self.assertEqual(response, '400')  # 300 + 100

        logger.info("E2E: chaincode query done")

    async def query_installed_chaincodes(self):
        """
        Test query installed chaincodes on peer

        :return:
        """
        logger.info("E2E: Query installed chaincode start")

        lifecycle = Lifecycle(self.client, CC_NAME)
        orgs = ["org1.example.com", "org2.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            responses = await lifecycle.query_installed_chaincodes(org_admin, ['peer0.' + org, 'peer1.' + org])

            self.assertEqual(responses[0]["installedChaincodes"][0]["label"], CC_NAME, "Query failed")
            self.assertEqual(responses[0]["installedChaincodes"][0]["packageId"], self.package_id, "Query failed")

        logger.info("E2E: Query installed chaincode done")

    async def query_approved_chaincodes(self):
        """
        Test query installed chaincodes on peer

        :return:
        """
        logger.info("E2E: Query installed chaincode start")

        lifecycle = Lifecycle(self.client, CC_NAME)
        orgs = ["org1.example.com", "org2.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            responses = await lifecycle.query_approved_chaincodes(org_admin, ['peer0.' + org, 'peer1.' + org],
                                                                  self.channel_name, CC_NAME, 0)
            self.assertTrue(responses[0])
            self.assertEqual(responses[0]["source"]["localPackage"]["packageId"], self.package_id, "Query failed")

        logger.info("E2E: Query installed chaincode done")

    async def query_committed_chaincodes(self):
        """
        Test query installed chaincodes on peer

        :return:
        """
        logger.info("E2E: Query installed chaincode start")

        lifecycle = Lifecycle(self.client, CC_NAME)
        orgs = ["org1.example.com", "org2.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            responses = await lifecycle.query_committed_chaincodes(org_admin, ['peer0.' + org, 'peer1.' + org],
                                                                   self.channel_name, CC_NAME)
            self.assertTrue(responses[0])

        logger.info("E2E: Query installed chaincode done")

    async def query_instantiated_chaincodes(self, cc_version=CC_VERSION):
        """
        Test query instantiated chaincodes on peer

        :return:
        """
        logger.info("E2E: Query instantiated chaincode start")

        orgs = ["org1.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")

            responses = await self.client.query_instantiated_chaincodes(
                requestor=org_admin,
                channel_name=self.channel_name,
                peers=['peer0.' + org, 'peer1.' + org],
            )
            self.assertTrue(len(responses) >= 1)
            self.assertEqual(
                responses[0].chaincodes[0].name, CC_NAME, "Query failed")
            self.assertEqual(
                responses[0].chaincodes[0].version, cc_version, "Query failed")
            self.assertEqual(
                responses[0].chaincodes[0].path, CC_PATH, "Query failed")

        logger.info("E2E: Query installed chaincode done")

    async def get_channel_config(self):
        """
        Test get channel config on peer

        :return:
        """
        logger.info(f"E2E: Get channel {self.channel_name} config start")

        orgs = ["org1.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            responses = await self.client.get_channel_config(
                requestor=org_admin,
                channel_name=self.channel_name,
                peers=['peer0.' + org, 'peer1.' + org]
            )
            self.assertEqual(responses[0].config.sequence,
                             1, "Get Config Failed")

        logger.info("E2E: Query installed chaincode done")

    async def get_channel_config_with_orderer(self, chname=SYSTEM_CHANNEL_NAME):
        """
        Test get channel config on orderer
         :return:
        """
        logger.info(f"E2E: Get channel {chname} config start")

        orgs = ["orderer.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            response = await self.client.get_channel_config_with_orderer(
                orderer='orderer.example.com',
                requestor=org_admin,
                channel_name=chname,
            )
            self.assertEqual(response['config']['sequence'],
                             '0', "Get Config Failed")

        logger.info(f"E2E: Get channel {chname} config done")

    def test_in_sequence(self):
        loop = asyncio.get_event_loop()

        logger.info("\n\nE2E testing started...")

        self.client.new_channel(SYSTEM_CHANNEL_NAME)

        loop.run_until_complete(self.get_channel_config_with_orderer())

        loop.run_until_complete(self.channel_create())

        loop.run_until_complete(self.channel_join())

        loop.run_until_complete(self.get_channel_config())

        loop.run_until_complete(self.chaincode_package())

        loop.run_until_complete(self.chaincode_install())

        loop.run_until_complete(self.query_installed_chaincodes())

        loop.run_until_complete(self.chaincode_approve_for_my_org())

        loop.run_until_complete(self.query_approved_chaincodes())

        loop.run_until_complete(self.commit_chaincode_def())

        loop.run_until_complete(self.query_committed_chaincodes())

        loop.run_until_complete(self.initialize_chaincode())

        loop.run_until_complete(self.chaincode_invoke())

        loop.run_until_complete(self.chaincode_invoke_fail())

        loop.run_until_complete(self.chaincode_invoke_fail_proposal())

        loop.run_until_complete(self.chaincode_query())

        logger.info("E2E all test cases done\n\n")


if __name__ == "__main__":
    unittest.main()
