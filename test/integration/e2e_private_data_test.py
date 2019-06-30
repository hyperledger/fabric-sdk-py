# Copyright IBM Corp. 2017 All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
import asyncio
import os
import time
import json
import docker
import logging
import unittest

from hfc.fabric.channel.channel import SYSTEM_CHANNEL_NAME

from hfc.util.policies import s2d

from hfc.fabric.client import Client
from test.integration.config import E2E_CONFIG
from test.integration.utils import BaseTestCase

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

CC_PATH = 'github.com/marbles_cc_private'
CC_NAME = 'marbles_cc_private'
CC_VERSION = '1.0'


class E2ePrivateDataTest(BaseTestCase):

    def setUp(self):
        self.gopath_bak = os.environ.get('GOPATH', '')
        gopath = os.path.normpath(os.path.join(os.path.dirname(__file__),
                                               "../fixtures/chaincode"))
        os.environ['GOPATH'] = os.path.abspath(gopath)
        self.channel_tx = \
            E2E_CONFIG['test-network']['channel-artifacts']['channel.tx']
        self.compose_file_path = \
            E2E_CONFIG['test-network']['docker']['compose_file_tls']

        self.config_yaml = \
            E2E_CONFIG['test-network']['channel-artifacts']['config_yaml']
        self.channel_profile = \
            E2E_CONFIG['test-network']['channel-artifacts']['channel_profile']
        self.client = Client('test/fixtures/network.json')
        self.channel_name = "businesschannel"  # default application channel
        self.user = self.client.get_user('org1.example.com', 'Admin')
        self.assertIsNotNone(self.user, 'org1 admin should not be None')

        # Boot up the testing network
        self.shutdown_test_env()
        self.start_test_env()
        time.sleep(1)

    def tearDown(self):
        super(E2ePrivateDataTest, self).tearDown()

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

    async def channel_update_anchors(self):

        orgs = ["org1.example.com", "org2.example.com"]

        anchors = [
            'test/fixtures/e2e_cli/channel-artifacts/' + msporg + 'anchors.tx'
            for msporg in ['Org1MSP', 'Org2MSP']
        ]

        for org, anchortx in zip(orgs, anchors):
            org_admin = self.client.get_user(org, "Admin")
            response = await self.client.channel_update(
                "orderer.example.com",
                self.channel_name,
                org_admin,
                config_tx=anchortx
            )

            self.assertTrue(response)

    async def chaincode_install(self):
        """
        Test installing an example chaincode to peer
        """
        logger.info("E2E: Chaincode install start")
        cc = f'/var/hyperledger/production/chaincodes/{CC_NAME}.{CC_VERSION}'

        # uncomment for testing with packaged_cc

        # create packaged chaincode before for having same id
        # code_package = package_chaincode(CC_PATH, CC_TYPE_GOLANG)

        orgs = ["org1.example.com", "org2.example.com"]
        for org in orgs:

            # simulate possible different chaincode archive based on timestamp
            time.sleep(2)

            org_admin = self.client.get_user(org, "Admin")
            responses = await self.client.chaincode_install(
                requestor=org_admin,
                peers=['peer0.' + org, 'peer1.' + org],
                cc_path=CC_PATH,
                cc_name=CC_NAME,
                cc_version=CC_VERSION,
                # packaged_cc=code_package
            )
            self.assertTrue(responses)
            # Verify the cc pack exists now in the peer node
            dc = docker.from_env()
            for peer in ['peer0', 'peer1']:
                peer_container = dc.containers.get(peer + '.' + org)
                code, output = peer_container.exec_run(f'test -f {cc}')
                self.assertEqual(code, 0, "chaincodes pack not exists")

        logger.info("E2E: chaincode install done")

    async def chaincode_instantiate(self):
        """
        Test instantiating an example chaincode to peer
        """
        logger.info("E2E: Chaincode instantiation start")

        org = "org1.example.com"

        policy = s2d().parse("OR('Org1MSP.member', 'Org2MSP.member')")

        collections_config = [
            {
                "name": "collectionMarbles",
                "policy": s2d().parse(
                    "OR('Org1MSP.member','Org2MSP.member')"
                ),
                "requiredPeerCount": 0,
                "maxPeerCount": 1,
                "blockToLive": 1000000,
                "memberOnlyRead": True
            },

            {
                "name": "collectionMarblePrivateDetails",
                "policy": s2d().parse(
                    "OR('Org1MSP.member')"
                ),
                "requiredPeerCount": 0,
                "maxPeerCount": 1,
                "blockToLive": 5,
                "memberOnlyRead": True
            }
        ]

        org_admin = self.client.get_user(org, "Admin")
        response = await self.client.chaincode_instantiate(
            requestor=org_admin,
            channel_name=self.channel_name,
            peers=['peer0.' + org],
            args=None,
            cc_name=CC_NAME,
            cc_version=CC_VERSION,
            cc_endorsement_policy=policy,
            collections_config=collections_config,
            wait_for_event=True
        )
        logger.info(
            "E2E: Chaincode instantiation response {}".format(response))
        policy = {
            'version': 0,
            'rule': {'n_out_of': {
                'n': 1,
                'rules': [
                    {'signed_by': 0},
                    {'signed_by': 1}
                ]}
            },
            'identities': [
                {
                    'principal_classification': 'ROLE',
                    'principal': {
                        'msp_identifier': 'Org1MSP',
                        'role': 'MEMBER'
                    }
                },
                {
                    'principal_classification': 'ROLE',
                    'principal': {
                        'msp_identifier': 'Org2MSP',
                        'role': 'MEMBER'
                    }
                },
            ]
        }

        self.assertEqual(response['name'], CC_NAME)
        self.assertEqual(response['version'], CC_VERSION)
        self.assertEqual(response['policy'], policy)
        logger.info("E2E: chaincode instantiation done")

    async def chaincode_invoke(self):
        """
        Test invoking an example chaincode to peer

        :return:
        """
        logger.info("E2E: Chaincode invoke start")

        orgs = ["org1.example.com"]
        marble = json.dumps({
            "name": "marble1",
            "color": "blue",
            "size": 35,
            "owner": "tom",
            "price": 99
        }).encode()

        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            response = await self.client.chaincode_invoke(
                requestor=org_admin,
                channel_name=self.channel_name,
                peers=['peer0.' + org],
                fcn='initMarble',
                args=None,
                cc_name=CC_NAME,
                wait_for_event=True,
                wait_for_event_timeout=120,
                transient_map={"marble": marble}
            )
            self.assertFalse(response)

        # Wait for gossip private data
        time.sleep(5)

        logger.info("E2E: chaincode invoke done")

    async def chaincode_query(self):
        """
        Test invoking an example chaincode to peer

        :return:
        """
        logger.info("E2E: Chaincode query start")

        orgs = ["org1.example.com"]

        args = ["marble1"]

        res = {
            "color": "blue",
            "docType": "marble",
            "name": "marble1",
            "owner": "tom",
            "size": 35
        }

        resp = {
            "docType": "marblePrivateDetails",
            "name": "marble1",
            "price": 99
        }

        for org in ["org1.example.com", "org2.example.com"]:
            org_admin = self.client.get_user(org, "Admin")
            response = await self.client.chaincode_query(
                requestor=org_admin,
                channel_name=self.channel_name,
                peers=['peer0.' + org],
                fcn="readMarble",
                args=args,
                cc_name=CC_NAME
            )
            self.assertEqual(json.loads(response), res)

        orgs = ["org1.example.com"]
        args = ["marble1"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            response = await self.client.chaincode_query(
                requestor=org_admin,
                channel_name=self.channel_name,
                peers=['peer0.' + org],
                fcn="readMarblePrivateDetails",
                args=args,
                cc_name=CC_NAME
            )
            self.assertEqual(json.loads(response), resp)

        orgs = ["org2.example.com"]
        args = ["marble1"]
        error = "does not have read access permission"
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            with self.assertRaises(Exception) as context:
                response = await self.client.chaincode_query(
                    requestor=org_admin,
                    channel_name=self.channel_name,
                    peers=['peer0.' + org],
                    fcn="readMarblePrivateDetails",
                    args=args,
                    cc_name=CC_NAME
                )
                self.assertTrue(error in str(context.exception))

        logger.info("E2E: chaincode query done")

    async def query_installed_chaincodes(self):
        """
        Test query installed chaincodes on peer

        :return:
        """
        logger.info("E2E: Query installed chaincode start")

        orgs = ["org1.example.com", "org2.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            responses = await self.client.query_installed_chaincodes(
                requestor=org_admin,
                peers=['peer0.' + org, 'peer1.' + org],
            )
            self.assertEqual(
                responses[0].chaincodes[0].name, CC_NAME, "Query failed")
            self.assertEqual(
                responses[0].chaincodes[0].version, CC_VERSION, "Query failed")
            self.assertEqual(
                responses[0].chaincodes[0].path, CC_PATH, "Query failed")

        logger.info("E2E: Query installed chaincode done")

    async def query_instantiated_chaincodes(self):
        """
        Test query instantiated chaincodes on peer

        :return:
        """
        logger.info("E2E: Query instantiated chaincode start")

        orgs = ["org1.example.com", "org2.example.com"]
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
                responses[0].chaincodes[0].version, CC_VERSION, "Query failed")
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

    async def get_channel_config_with_orderer(self,
                                              chname=SYSTEM_CHANNEL_NAME):
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

        loop.run_until_complete(self.channel_update_anchors())

        loop.run_until_complete(self.get_channel_config())

        loop.run_until_complete(self.chaincode_install())

        loop.run_until_complete(self.query_installed_chaincodes())

        loop.run_until_complete(self.chaincode_instantiate())

        loop.run_until_complete(self.query_instantiated_chaincodes())

        loop.run_until_complete(self.chaincode_invoke())

        loop.run_until_complete(self.chaincode_query())

        logger.info("E2E private data all test cases done\n\n")


if __name__ == "__main__":
    unittest.main()
