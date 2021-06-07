# SPDX-License-Identifier: Apache-2.0

import asyncio
import time
from asyncio import shield

import docker
import logging
import unittest

from hfc.fabric.channel.channel import SYSTEM_CHANNEL_NAME
from hfc.fabric.chaincode import ChaincodeExecutionError
from hfc.util.policies import s2d

from test.integration.utils import BaseTestCase

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

CC_PATH = 'github.com/example_cc_with_event'
CC_NAME = 'example_cc_with_event'
CC_VERSION = '1.0'
CC_UPGRADED_VERSION = '1.1'
TOTAL_BLOCKS = 6


class E2eTest(BaseTestCase):

    def setUp(self):
        super(E2eTest, self).setUp()

    def tearDown(self):
        super(E2eTest, self).tearDown()

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

    async def chaincode_install(self, cc_version=CC_VERSION):
        """
        Test installing an example chaincode to peer
        """
        logger.info("E2E: Chaincode install start")
        cc = f'/var/hyperledger/production/chaincodes/{CC_NAME}.{cc_version}'

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
                cc_version=cc_version,
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

    def chaincode_install_fail(self):
        pass

    async def chaincode_instantiate(self):
        """
        Test instantiating an example chaincode to peer
        """
        logger.info("E2E: Chaincode instantiation start")

        org = "org1.example.com"
        args = ['a', '200', 'b', '300']

        # policy = s2d().parse("OR('Org1MSP.member', 'Org1MSP.admin')")
        policy = s2d().parse("OR('Org1MSP.member')")

        org_admin = self.client.get_user(org, "Admin")
        response = await self.client.chaincode_instantiate(
            requestor=org_admin,
            channel_name=self.channel_name,
            peers=['peer0.' + org],
            args=args,
            cc_name=CC_NAME,
            cc_version=CC_VERSION,
            cc_endorsement_policy=policy,
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
                    # {'signed_by': 1}
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
                # {
                #     'principal_classification': 'ROLE',
                #     'principal': {
                #         'msp_identifier': 'Org1MSP',
                #         'role': 'ADMIN'
                #     }
                # },
            ]
        }
        self.assertEqual(response['name'], CC_NAME)
        self.assertEqual(response['version'], CC_VERSION)
        self.assertEqual(response['policy'], policy)
        logger.info("E2E: chaincode instantiation done")

    async def chaincode_upgrade(self, cc_version):
        """
        Test upgrading an example chaincode
        """
        logger.info("E2E: Chaincode upgrade start")

        org = "org1.example.com"
        args = ['a', '200', 'b', '300']

        # policy = s2d().parse("OR('Org1MSP.member', 'Org1MSP.admin')")
        policy = s2d().parse("OR('Org1MSP.member')")

        org_admin = self.client.get_user(org, "Admin")
        response = await self.client.chaincode_upgrade(
            requestor=org_admin,
            channel_name=self.channel_name,
            peers=['peer0.' + org],
            args=args,
            cc_name=CC_NAME,
            cc_version=cc_version,
            cc_endorsement_policy=policy,
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
                    # {'signed_by': 1}
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
                # {
                #     'principal_classification': 'ROLE',
                #     'principal': {
                #         'msp_identifier': 'Org1MSP',
                #         'role': 'ADMIN'
                #     }
                # },
            ]
        }
        self.assertEqual(response['name'], CC_NAME)
        self.assertEqual(response['version'], cc_version)
        self.assertEqual(response['policy'], policy)
        logger.info("E2E: chaincode instantiation done")

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
                wait_for_event=True,
                wait_for_event_timeout=120,
                cc_pattern="^invoked*"  # for chaincode event
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
                    wait_for_event=True,
                    wait_for_event_timeout=120,
                    cc_pattern="^invoked*"  # for chaincode event
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
                    wait_for_event_timeout=120,
                    cc_pattern="^invoked*",  # for chaincode event,
                    raise_on_error=True
                )

        logger.info("E2E: chaincode invoke failed proposal done")

    async def chaincode_channel_event_hub(self):
        """
        Test invoking an example chaincode to peer

        :return:
        """
        logger.info("E2E: Chaincode Channel Event Hub test start")

        def onEvent(cc_event, block_number, tx_id, tx_status):
            self.ceh.unregisterChaincodeEvent(self.cr1)
            self.ceh.unregisterChaincodeEvent(self.cr2)
            self.ceh.unregisterChaincodeEvent(self.cr3)
            self.ceh.disconnect()

        orgs = ["org1.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            # register extra chaincode event
            channel = self.client.get_channel(self.channel_name)
            target_peer = self.client.get_peer('peer1.' + org)
            self.ceh = channel.newChannelEventHub(target_peer, org_admin)
            stream = self.ceh.connect()
            self.cr1 = self.ceh.registerChaincodeEvent(CC_NAME, 'invoked')
            self.cr2 = self.ceh.registerChaincodeEvent(CC_NAME, 'invoked')
            self.cr3 = self.ceh.registerChaincodeEvent(CC_NAME, 'invoked',
                                                       onEvent=onEvent)

            await asyncio.wait_for(asyncio.gather(stream,
                                                  return_exceptions=True),
                                   timeout=120)

        logger.info("E2E: Chaincode Channel Event Hub test done")

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

    async def query_channels(self):
        """
        Test querying channel

        :return:
        """
        logger.info("E2E: Query channel start")

        orgs = ["org1.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            response = await self.client.query_channels(
                requestor=org_admin,
                peers=['peer0.' + org, 'peer1.' + org],
            )
            self.assertEqual(
                response.channels[0].channel_id,
                self.channel_name,
                "Query failed")

        logger.info("E2E: Query channel done")

    async def query_info(self):
        """
        Test querying information on the state of the Channel

        :return:
        """
        logger.info("E2E: Query info start")

        orgs = ["org1.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            response = await self.client.query_info(
                requestor=org_admin,
                channel_name=self.channel_name,
                peers=['peer0.' + org, 'peer1.' + org],
            )
            self.assertEqual(
                response.height,
                TOTAL_BLOCKS,
                "Query failed")

        logger.info("E2E: Query info done")

    async def query_block_by_txid(self):
        """
        Test querying block by tx id

        :return:
        """
        logger.info("E2E: Query block by tx id start")

        orgs = ["org1.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")

            response = await self.client.query_info(
                requestor=org_admin,
                channel_name=self.channel_name,
                peers=['peer0.' + org, 'peer1.' + org],
            )

            response = await self.client.query_block_by_hash(
                requestor=org_admin,
                channel_name=self.channel_name,
                peers=['peer0.' + org, 'peer1.' + org],
                block_hash=response.currentBlockHash
            )

            tx_id = response.get('data').get('data')[0].get(
                'payload').get('header').get(
                'channel_header').get('tx_id')

            response = await self.client.query_block_by_txid(
                requestor=org_admin,
                channel_name=self.channel_name,
                peers=['peer0.' + org, 'peer1.' + org],
                tx_id=tx_id
            )

            self.assertEqual(
                response.get('data').get('data')[0].get(
                    'payload').get('header').get(
                    'channel_header').get('tx_id'),
                tx_id,
                "Query failed")

        logger.info("E2E: Query block by tx id done")

    async def query_block_by_hash(self):
        """
        Test querying block by block hash

        :return:
        """
        logger.info("E2E: Query block by block hash start")

        orgs = ["org1.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")

            response = await self.client.query_info(
                requestor=org_admin,
                channel_name=self.channel_name,
                peers=['peer0.' + org, 'peer1.' + org],
            )

            previous_block_hash = response.previousBlockHash
            current_block_hash = response.currentBlockHash
            response = await self.client.query_block_by_hash(
                requestor=org_admin,
                channel_name=self.channel_name,
                peers=['peer0.' + org, 'peer1.' + org],
                block_hash=current_block_hash
            )

            self.assertEqual(
                response['header']['previous_hash'].decode('utf-8'),
                previous_block_hash.hex(),
                "Query failed")

        logger.info("E2E: Query block by block hash done")

    async def query_block(self):
        """
        Test querying block by block number

        :return:
        """
        logger.info("E2E: Query block by block number start")

        orgs = ["org1.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")
            response = await self.client.query_block(
                requestor=org_admin,
                channel_name=self.channel_name,
                peers=['peer0.' + org, 'peer1.' + org],
                block_number='0'
            )
            self.assertEqual(
                response['header']['number'],
                0,
                "Query failed")
            self.blockheader = response['header']

        logger.info("E2E: Query block by block number done")

    async def query_transaction(self):
        """
        Test querying transaction by tx id

        :return:
        """
        logger.info("E2E: Query transaction by tx id start")
        orgs = ["org1.example.com"]
        for org in orgs:
            org_admin = self.client.get_user(org, "Admin")

            response = await self.client.query_info(
                requestor=org_admin,
                channel_name=self.channel_name,
                peers=['peer0.' + org, 'peer1.' + org],
            )

            response = await self.client.query_block_by_hash(
                requestor=org_admin,
                channel_name=self.channel_name,
                peers=['peer0.' + org, 'peer1.' + org],
                block_hash=response.currentBlockHash
            )

            tx_id = response.get('data').get('data')[0].get(
                'payload').get('header').get(
                'channel_header').get('tx_id')

            response = await self.client.query_transaction(
                requestor=org_admin,
                channel_name=self.channel_name,
                peers=['peer0.' + org, 'peer1.' + org],
                tx_id=tx_id
            )

            self.assertEqual(
                response.get('transaction_envelope').get('payload').get(
                    'header').get('channel_header').get('channel_id'),
                self.channel_name,
                "Query failed")

        logger.info("E2E: Query transaction by tx id done")

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

    def onFilteredEvent(self, block):
        self.filtered_blocks.append(block)

    async def get_filtered_block_events(self):

        org = 'org1.example.com'
        peer = self.client.get_peer('peer0.' + org)

        org_admin = self.client.get_user(org, 'Admin')
        channel = self.client.get_channel(self.channel_name)
        channel_event_hub = channel.newChannelEventHub(peer, org_admin)
        stream = channel_event_hub.connect(filtered=True,
                                           start='oldest', stop='newest')

        self.filtered_blocks = []
        channel_event_hub.registerBlockEvent(unregister=False,
                                             onEvent=self.onFilteredEvent)

        try:
            await shield(stream)
        except Exception:
            pass

        channel_event_hub.disconnect()

        self.assertEqual(len(self.filtered_blocks), TOTAL_BLOCKS)

        block = self.filtered_blocks[0]
        self.assertEqual(block['number'], 0)
        self.assertEqual(block['channel_id'], self.channel_name)

        filtered_transaction = block['filtered_transactions'][0]
        self.assertEqual(filtered_transaction['tx_validation_code'], 'VALID')
        self.assertEqual(filtered_transaction['txid'], '')
        self.assertEqual(filtered_transaction['type'], 'CONFIG')

    def onFullEvent(self, block):
        self.blocks.append(block)

    async def get_full_block_events(self):

        org = 'org1.example.com'
        peer = self.client.get_peer('peer0.' + org)

        org_admin = self.client.get_user(org, 'Admin')
        channel = self.client.get_channel(self.channel_name)
        channel_event_hub = channel.newChannelEventHub(peer, org_admin)
        stream = channel_event_hub.connect(start='oldest',
                                           stop='newest', filtered=False)

        self.blocks = []
        channel_event_hub.registerBlockEvent(unregister=False,
                                             onEvent=self.onFullEvent)

        try:
            await shield(stream)
        except Exception:
            pass

        channel_event_hub.disconnect()

        self.assertEqual(len(self.blocks), TOTAL_BLOCKS)

        block = self.blocks[0]
        self.assertEqual(block['header']['number'], 0)

        block = self.blocks[2]
        self.assertEqual(block['header']['number'], 2)
        action = block['data']['data'][0]['payload']['data']['actions'][0]
        ppl_r_p = action['payload']['action']['proposal_response_payload']
        events_obj = ppl_r_p['extension']['events']
        self.assertEqual(events_obj['event_name'], 'invoked')
        self.assertEqual(events_obj['chaincode_id'], CC_NAME)
        self.assertEqual(events_obj['payload'], b'400')

    def onTxEvent(self, tx_id, status, block_number):

        o = {
            'status': status,
            'block_number': block_number
        }

        if tx_id == 'all':
            if tx_id not in self.txs:
                self.txs[tx_id] = []
            self.txs[tx_id] += [o]
        else:
            self.txs[tx_id] = o

    async def get_tx_events(self):

        org = 'org1.example.com'
        peer = self.client.get_peer('peer0.' + org)

        org_admin = self.client.get_user(org, 'Admin')
        channel = self.client.get_channel(self.channel_name)
        channel_event_hub = channel.newChannelEventHub(peer, org_admin)
        stream = channel_event_hub.connect(start='oldest',
                                           stop='newest', filtered=False)

        self.txs = {}
        channel_event_hub.registerTxEvent('all', onEvent=self.onTxEvent)

        try:
            await shield(stream)
        except Exception:
            pass

        channel_event_hub.disconnect()

        self.assertEqual(len(self.txs['all']), TOTAL_BLOCKS)

    def test_in_sequence(self):

        loop = asyncio.get_event_loop()

        logger.info("\n\nE2E testing started...")

        self.client.new_channel(SYSTEM_CHANNEL_NAME)

        loop.run_until_complete(self.get_channel_config_with_orderer())

        loop.run_until_complete(self.channel_create())

        loop.run_until_complete(self.channel_join())

        loop.run_until_complete(self.get_channel_config())

        loop.run_until_complete(self.chaincode_install())

        self.chaincode_install_fail()

        loop.run_until_complete(self.query_installed_chaincodes())

        loop.run_until_complete(self.chaincode_instantiate())

        loop.run_until_complete(self.query_instantiated_chaincodes())

        loop.run_until_complete(self.chaincode_invoke())

        loop.run_until_complete(self.chaincode_invoke_fail())

        loop.run_until_complete(self.chaincode_invoke_fail_proposal())

        loop.run_until_complete(self.chaincode_channel_event_hub())

        loop.run_until_complete(self.chaincode_query())

        loop.run_until_complete(self.chaincode_install(CC_UPGRADED_VERSION))

        loop.run_until_complete(self.chaincode_upgrade(CC_UPGRADED_VERSION))

        loop.run_until_complete(self.query_instantiated_chaincodes(CC_UPGRADED_VERSION))

        loop.run_until_complete(self.chaincode_invoke())

        loop.run_until_complete(self.chaincode_query())

        loop.run_until_complete(self.query_channels())

        loop.run_until_complete(self.query_info())

        loop.run_until_complete(self.query_block_by_txid())

        loop.run_until_complete(self.query_block_by_hash())

        loop.run_until_complete(self.query_block())

        loop.run_until_complete(self.query_transaction())

        loop.run_until_complete(self.get_filtered_block_events())

        loop.run_until_complete(self.get_full_block_events())

        loop.run_until_complete(self.get_tx_events())

        logger.info("E2E all test cases done\n\n")


if __name__ == "__main__":
    unittest.main()
