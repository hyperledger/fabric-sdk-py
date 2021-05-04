# Copyright O Corp. 2019 All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

import os
import asyncio
from hfc.fabric import Client
from hfc.fabric.channel.channel import SYSTEM_CHANNEL_NAME

CONNECTION_PROFILE_PATH = 'test/fixtures/network.json'
CONFIG_YAML_PATH = 'test/fixtures/e2e_cli/'
CHAINCODE_PATH = 'test/fixtures/chaincode'
CC_PATH = 'github.com/example_cc_with_event'
CC_NAME = 'example_cc_with_event'
CC_VERSION = '1.0'

if __name__ == "__main__":
    cli = Client(net_profile=CONNECTION_PROFILE_PATH)
    loop = asyncio.get_event_loop()

    print(cli.organizations)  # orgs in the network
    print(cli.peers)  # peers in the network
    print(cli.orderers)  # orderers in the network
    print(cli.CAs)  # ca nodes in the network, TODO

    # get the admin user from local path
    org1_admin = cli.get_user(org_name='org1.example.com', name='Admin')

    # Create a New Channel, the response should be true if succeed
    response = loop.run_until_complete(cli.channel_create(
        orderer='orderer.example.com',
        channel_name='businesschannel',
        requestor=org1_admin,
        config_yaml=CONFIG_YAML_PATH,
        channel_profile='TwoOrgsChannel'
    ))
    if response:
        print("Create channel successful")
    else:
        print("Create channel failed")
        print(response)
        exit(-1)

    # Join Peers into Channel, the response should be true if succeed
    response = loop.run_until_complete(cli.channel_join(
        requestor=org1_admin,
        channel_name='businesschannel',
        peers=['peer0.org1.example.com', 'peer1.org1.example.com'],
        orderer='orderer.example.com'))
    if response:
        print("Join channel successful")
    else:
        print("Join channel failed")
        exit(-1)

    # Join Peers from a different MSP into Channel
    org2_admin = cli.get_user(org_name='org2.example.com', name='Admin')

    # org2_admin is required to operate peers of org2.example.com
    response = loop.run_until_complete(cli.channel_join(
        requestor=org2_admin,
        channel_name='businesschannel',
        peers=['peer0.org2.example.com', 'peer1.org2.example.com'],
        orderer='orderer.example.com'))
    if response:
        print("Join channel successful")
    else:
        print("Join channel failed")
        exit(-1)

    # Install Chaincode to Peers
    # This is only needed if to use the example chaincode inside sdk
    gopath_bak = os.environ.get('GOPATH', '')
    gopath = os.path.normpath(os.path.join(
        os.path.dirname(os.path.realpath('__file__')),
        CHAINCODE_PATH
    ))
    os.environ['GOPATH'] = os.path.abspath(gopath)

    # The response should be true if succeed
    response = loop.run_until_complete(cli.chaincode_install(
        requestor=org1_admin,
        peers=['peer0.org1.example.com', 'peer1.org1.example.com'],
        cc_path=CC_PATH,
        cc_name=CC_NAME,
        cc_version=CC_VERSION))

    # Instantiate Chaincode in Channel, the response should be true if succeed
    args = ['a', '200', 'b', '300']
    response = loop.run_until_complete(cli.chaincode_instantiate(
        requestor=org1_admin,
        channel_name='businesschannel',
        peers=['peer0.org1.example.com'],
        args=args,
        cc_name=CC_NAME,
        cc_version=CC_VERSION))
    if response:
        print("Instantiate chaincode successful")
    else:
        print("Instantiate chaincode failed")
        exit(-1)

    # Invoke a chaincode
    args = ['a', 'b', '100']
    # The response should be true if succeed
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org1_admin,
        channel_name='businesschannel',
        peers=['peer0.org1.example.com'],
        args=args,
        cc_name=CC_NAME
    ))
    print("Invoke chaincode done.")
    print(response)

    # Query a chaincode
    args = ['b']
    # The response should be true if succeed
    response = loop.run_until_complete(cli.chaincode_query(
        requestor=org1_admin,
        channel_name='businesschannel',
        peers=['peer0.org1.example.com'],
        args=args,
        cc_name=CC_NAME
    ))
    print("Query chaincode done.")
    print(response)

    # Query Peer installed chaincodes
    response = loop.run_until_complete(cli.query_installed_chaincodes(
        requestor=org1_admin,
        peers=['peer0.org1.example.com']
    ))
    print("Query installed chaincode.")
    print(response)

    # Get channel config
    response = loop.run_until_complete(cli.get_channel_config(
        requestor=org1_admin,
        channel_name='businesschannel',
        peers=['peer0.org1.example.com']
    ))
    print("Get channel config done.")
    print(response)

    # Channel event hub
    def getBlocks(blocks):
        # On event complition the block is appended to the list of blocks
        def onEvent(block):
            blocks.append(block)
        # Returns an instance of the onEvent function
        return onEvent

    blocks = []  # empty list

    channel = cli.get_channel('businesschannel')
    channel_event_hub = channel.newChannelEventHub(cli.get_peer('peer0.org1.example.com'), org1_admin)
    channel_event_hub.registerBlockEvent(start=0, onEvent=getBlocks(blocks))

    stream = channel_event_hub.connect()
    print(blocks)

    # Query Channel
    response = cli.query_channels(
        requestor=org1_admin,
        peers=['peer0.org1.example.com', 'peer1.org1.example.com']
    )
    print(response)

    # Query Info
    response = loop.run_until_complete(cli.query_info(
        requestor=org1_admin,
        channel_name='businesschannel',
        peers=['peer0.org1.example.com', 'peer1.org1.example.com']
    ))
    print(response)

    # The info acquired from the query_info is used to query block by hash
    response = loop.run_until_complete(cli.query_block_by_hash(
        requestor=org1_admin,
        channel_name='businesschannel',
        peers=['peer0.org1.example.com', 'peer1.org1.example.com'],
        block_hash=response.currentBlockHash
    ))
    print(response)

    # TxID is extracted from the block information
    tx_id = response.get('data').get('data')[0].get(
        'payload').get('header').get(
        'channel_header').get('tx_id')

    # Query block by txid
    response = loop.run_until_complete(cli.query_block_by_txid(
        requestor=org1_admin,
        channel_name='businesschannel',
        peers=['peer0.org1.example.com', 'peer1.org1.example.com'],
        tx_id=tx_id
    ))
    print(response)

    # Query by block number
    response = loop.run_until_complete(cli.query_block(
        requestor=org1_admin,
        channel_name='businesschannel',
        peers=['peer0.org1.example.com', 'peer1.org1.example.com'],
        block_number='0'
    ))
    print(response)

    # Query instantiated chaincodes
    responses = loop.run_until_complete(cli.query_instantiated_chaincodes(
        requestor=org1_admin,
        channel_name='businesschannel',
        peers=['peer0.org1.example.com', 'peer1.org1.example.com']
    ))
    print(responses)

    # Get Channel configuration
    responses = loop.run_until_complete(cli.get_channel_config(
        requestor=org1_admin,
        channel_name='businesschannel',
        peers=['peer0.org1.example.com', 'peer1.org1.example.com']
    ))
    print(responses)

    # Get channel config from orderer
    response = loop.run_until_complete(cli.get_channel_config_with_orderer(
        orderer='orderer.example.com',
        requestor=org1_admin,
        channel_name=SYSTEM_CHANNEL_NAME,
    ))
    print(response)
