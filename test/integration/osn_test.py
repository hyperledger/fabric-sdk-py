# SPDX-License-Identifier: Apache-2.0

import asyncio
import os
import subprocess
import time
import logging
import unittest

from hfc.fabric.osnadmin import OSNAdmin, OSNOperationException
from hfc.fabric.client import Client
from test.integration.config import E2E_CONFIG
from test.integration.utils import BaseTestCase

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


ORDERER_ADMIN_TLS_CERT = "test/fixtures/lifecycle_2_0/crypto-config/ordererOrganizations/example.com/users/Admin@example.com/tls/client.crt"  # noqa: E501
ORDERER_ADMIN_TLS_KEY = "test/fixtures/lifecycle_2_0/crypto-config/ordererOrganizations/example.com/users/Admin@example.com/tls/client.key"  # noqa: E501
ORDERER_ADMIN_TLS_CA = "test/fixtures/lifecycle_2_0/crypto-config/ordererOrganizations/example.com/users/Admin@example.com/tls/ca.crt"  # noqa: E501


class OSNTests(BaseTestCase):
    def setUp(self):
        self.compose_file_path = \
            E2E_CONFIG['test-network']['docker']['compose_file_osn']

        self.config_yaml = \
            E2E_CONFIG['test-network']['channel-artifacts']['osn_config_yaml']
        self.channel_profile = \
            E2E_CONFIG['test-network']['channel-artifacts']['channel_profile']
        self.client = Client('test/fixtures/network_osn.json')

        self.channel_name = "businesschannel"  # default application channel
        self.client.new_channel(self.channel_name)
        self.user = self.client.get_user('org1.example.com', 'Admin')
        self.orderers_eps = [
            "https://localhost:9443",
            "https://localhost:10443",
            "https://localhost:11443"
        ]
        self.assertIsNotNone(self.user, 'org1 admin should not be None')

        self.conf_block = self.generate_channel_block(
            self.channel_name,
            self.config_yaml,
            self.channel_profile
        )

        # Boot up the testing network
        self.shutdown_test_env()
        self.start_test_env()
        time.sleep(2)

    def tearDown(self):
        super(OSNTests, self).tearDown()

    def generate_channel_block(self, channel_name, cfg_path, channel_profile):
        if 'fabric-bin/bin' not in os.environ['PATH']:
            executable_path = os.path.join(
                os.path.dirname(__file__).rsplit('/', 2)[0], 'fabric-bin/bin')
            os.environ['PATH'] += os.pathsep + executable_path

        # Generate channel.tx with configtxgen
        tx_path = "/tmp/channel.block"
        cfg_path = cfg_path if os.path.isabs(cfg_path) else \
            os.getcwd() + "/" + cfg_path

        new_env = dict(os.environ, FABRIC_CFG_PATH=cfg_path)
        output = subprocess.Popen(['configtxgen',
                                   '-configPath', cfg_path,
                                   '-profile', channel_profile,
                                   '-channelID', channel_name,
                                   '-outputBlock', tx_path],
                                  stdout=open(os.devnull, "w"),
                                  stderr=subprocess.PIPE, env=new_env)
        err = output.communicate()[1]
        if output.returncode:
            print('Failed to generate transaction file', err)
            return self.channel_name
        return tx_path

    def channel_create(self):
        """
        Create a channel

        :return:
        """
        logger.info(f"OSN: Channel creation start: name={self.channel_name}")

        # By default, self.user is the admin of org1
        self.assertTrue(self.conf_block)
        osn_admin = OSNAdmin(
            self.orderers_eps[0],
            ORDERER_ADMIN_TLS_CERT,
            ORDERER_ADMIN_TLS_KEY,
            ORDERER_ADMIN_TLS_CA,
        )
        res = osn_admin.list_all_channels()
        self.assertIsNone(res["systemChannel"])
        self.assertIsNone(res["channels"])
        res = osn_admin.join(self.conf_block)
        self.assertTrue(res)
        self.assertEqual(res["name"], self.channel_name)

        logger.info(f"OSN: Channel creation done: name={self.channel_name}")

    async def channel_join(self):
        """
        Join orderers into an existing channels

        :return:
        """

        logger.info(f"OSN: Channel join start: name={self.channel_name}")

        for orderer in self.orderers_eps[1:]:
            osn_admin = OSNAdmin(
                orderer,
                ORDERER_ADMIN_TLS_CERT,
                ORDERER_ADMIN_TLS_KEY,
                ORDERER_ADMIN_TLS_CA,
            )
            res = osn_admin.list_all_channels()
            self.assertIsNone(res["systemChannel"])
            self.assertIsNone(res["channels"])
            res = osn_admin.join(self.conf_block)
            self.assertTrue(res)
            res = osn_admin.list_single_channel(self.channel_name)
            self.assertTrue(res)
            self.assertEqual(res["status"], 'active')

        # fetch config to ensure that cluster is operational
        time.sleep(3)
        await self.client.get_channel_config_with_orderer(
            self.user,
            self.channel_name,
            self.client.orderers.get("orderer.example.com"),
            False
        )
        logger.info(f"OSN: Channel join done: name={self.channel_name}")

    def channel_remove(self):
        """
        Remove orderer from an existing channels

        :return:
        """
        logger.info(f"OSN: Channel remove start: name={self.channel_name}")

        osn_admin = OSNAdmin(
            self.orderers_eps[-1],
            ORDERER_ADMIN_TLS_CERT,
            ORDERER_ADMIN_TLS_KEY,
            ORDERER_ADMIN_TLS_CA,
        )
        res = osn_admin.list_single_channel(self.channel_name)
        self.assertTrue(res)
        self.assertEqual(res["status"], 'active')
        osn_admin.remove(self.channel_name)
        res = osn_admin.list_single_channel(self.channel_name)
        self.assertEqual(res["status"], 'inactive')

        logger.info(f"OSN: Channel remove done: name={self.channel_name}")

    def channel_list_nonexistent(self):
        """
        List nonexistent channel

        :return:
        """
        logger.info("OSN: Channel list with exception start")

        osn_admin = OSNAdmin(
            self.orderers_eps[0],
            ORDERER_ADMIN_TLS_CERT,
            ORDERER_ADMIN_TLS_KEY,
            ORDERER_ADMIN_TLS_CA,
        )
        self.assertRaises(
            OSNOperationException,
            osn_admin.list_single_channel,
            "nonexistent-channel"
        )

        logger.info("OSN: Channel list with exception done")

    def channel_join_existing(self):
        """
        Join orderer to the channel it's already a member of

        :return:
        """
        logger.info("OSN: Channel list with exception start")

        osn_admin = OSNAdmin(
            self.orderers_eps[0],
            ORDERER_ADMIN_TLS_CERT,
            ORDERER_ADMIN_TLS_KEY,
            ORDERER_ADMIN_TLS_CA,
        )

        self.assertRaises(
            OSNOperationException,
            osn_admin.join,
            self.conf_block
        )

        logger.info("OSN: Channel list with exception done")

    def test_in_sequence(self):
        loop = asyncio.get_event_loop()

        logger.info("\n\nOSN admin testing started...")

        self.channel_create()
        loop.run_until_complete(self.channel_join())
        self.channel_remove()
        self.channel_list_nonexistent()
        self.channel_join_existing()

        logger.info("OSN admin all test cases done\n\n")


if __name__ == "__main__":
    unittest.main()
