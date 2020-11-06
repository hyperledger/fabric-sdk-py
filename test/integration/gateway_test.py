# SPDX-License-Identifier: Apache-2.0

import asyncio
import logging
import copy

from hfc.fabric_network.gateway import Gateway
from hfc.fabric_network.network import Network
from test.integration.utils import BaseTestCase

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class GatewayTest(BaseTestCase):
    def test_gateway(self):
        loop = asyncio.get_event_loop()

        org1 = 'org1.example.com'
        # Channel Create
        response = loop.run_until_complete(
            self.client.channel_create('orderer.example.com',
                                       self.channel_name,
                                       self.user,
                                       config_yaml=self.config_yaml,
                                       channel_profile=self.channel_profile))
        logger.debug(response)
        self.assertTrue(response)

        # Channel join
        channel = self.client.get_channel(self.channel_name)
        self.assertIsNotNone(channel)

        response = loop.run_until_complete(self.client.channel_join(
            requestor=self.user,
            channel_name=self.channel_name,
            peers=['peer0.' + org1, 'peer1.' + org1],
            orderer='orderer.example.com'
        ))
        self.assertTrue(response)

        # Create Gateway connection
        new_gateway = Gateway()

        defaultOptions = dict({
            'top1': {
                'inner11': 10,
                'inner12': 'ten'
            },
            'top2': {
                'inner21': 20,
                'inner22': 'twenty'
            }
        })

        overrideOptions = dict({
            'top1': {
                'top13': {
                    'inner131': 131
                }
            }
        })

        expectedOptions = dict({
            'top1': {
                'inner11': 10,
                'inner12': 'ten',
                'top13': {
                    'inner131': 131
                }
            },
            'top2': {
                'inner21': 20,
                'inner22': 'twenty'
            }
        })

        currentOptions = copy.deepcopy(defaultOptions)
        result = new_gateway.mergeOptions(currentOptions, overrideOptions)
        self.assertDictEqual(expectedOptions, result)

        overrideOptions = {
            'top1': {
                'inner11': 20,
                'inner12': 'twenty'
            },
        }
        expectedOptions = {
            'top1': {
                'inner11': 20,
                'inner12': 'twenty'
            },
            'top2': {
                'inner21': 20,
                'inner22': 'twenty'
            }
        }

        currentOptions = copy.deepcopy(defaultOptions)
        result = new_gateway.mergeOptions(currentOptions, overrideOptions)
        self.assertDictEqual(expectedOptions, result)

        overrideOptions = {
            'top1': {
                'inner11': 20
            },
        }
        expectedOptions = {
            'top1': {
                'inner11': 20,
                'inner12': 'ten'
            },
            'top2': {
                'inner21': 20,
                'inner22': 'twenty'
            }
        }

        currentOptions = copy.deepcopy(defaultOptions)
        result = new_gateway.mergeOptions(currentOptions, overrideOptions)
        self.assertDictEqual(expectedOptions, result)

        overrideOptions = {
            'top1': {
                'inner11': None
            },
        }
        expectedOptions = {
            'top1': {
                'inner11': None,
                'inner12': 'ten'
            },
            'top2': {
                'inner21': 20,
                'inner22': 'twenty'
            }
        }

        currentOptions = copy.deepcopy(defaultOptions)
        result = new_gateway.mergeOptions(currentOptions, overrideOptions)
        self.assertDictEqual(expectedOptions, result)

        overrideOptions = {
            'single': True
        }
        expectedOptions = {
            'top1': {
                'inner11': 10,
                'inner12': 'ten'
            },
            'top2': {
                'inner21': 20,
                'inner22': 'twenty'
            },
            'single': True
        }

        currentOptions = copy.deepcopy(defaultOptions)
        result = new_gateway.mergeOptions(currentOptions, overrideOptions)
        self.assertDictEqual(expectedOptions, result)

        # TODO: Change this after wallet has been integrated
        options = {'wallet': ''}
        loop.run_until_complete(new_gateway.connect('test/fixtures/network.json', options))
        new_network = loop.run_until_complete(new_gateway.get_network(self.channel_name, self.user))

        self.assertTrue(isinstance(new_network, Network))
        self.assertTrue(self.channel_name in new_gateway.client._channels)
