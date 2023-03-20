# Tutorial of Using Fabric Python SDK

TLDR, run a quick testing.

```bash
$ HLF_VERSION=1.4.6
$ docker pull hyperledger/fabric-peer:${HLF_VERSION} \
    && docker pull hyperledger/fabric-orderer:${HLF_VERSION} \
    && docker pull hyperledger/fabric-ca:${HLF_VERSION} \
    && docker pull hyperledger/fabric-ccenv:${HLF_VERSION}
$ docker-compose -f test/fixtures/docker-compose-2orgs-4peers-tls.yaml up
$ pip3 install virtualenv; make venv
$ source venv/bin/activate
$ make install
$ tox -e py3 -- test/integration/e2e_test.py # Run specified test case
$ deactive
```

## 0. Prepare a Testing Environment

### 0.1. Install Fabric SDK

```bash
$ git clone https://github.com/hyperledger/fabric-sdk-py.git
$ cd fabric-sdk-py
$ make install
```

Optionally, you can also verify the version number or run all testing cases.

```bash
$ python
>>> import hfc
>>> print(hfc.VERSION)
0.9.0
>>> exit()

$ make check
```

### 0.2. Setup a Fabric Network

If you already have a running fabric network, ignore this.

To start an example fabric network you can simply run the following commands:

```bash
$ HLF_VERSION=1.4.6
$ docker pull hyperledger/fabric-peer:${HLF_VERSION}
$ docker pull hyperledger/fabric-orderer:${HLF_VERSION}
$ docker pull hyperledger/fabric-ca:${HLF_VERSION}
$ docker pull hyperledger/fabric-ccenv:${HLF_VERSION}
$ docker-compose -f test/fixtures/docker-compose-2orgs-4peers-tls.yaml up
```

Then you'll have a fabric network with 3 organizations, 4 peers and 1 orderer:
 * org1.example.com
   * peer0.org1.example.com
   * peer1.org1.example.com
 * org2.example.com
   * peer0.org2.example.com
   * peer1.org2.example.com
 * orderer.example.com
   * orderer.example.com

* Note: make sure `configtxgen` is in the '$PATH'.

If you want to understand more details on starting up a fabric network, feel free to see the [Building Your First Network](https://hyperledger-fabric.readthedocs.io/en/latest/build_network.html) tutorial.

### 0.3. Create the Connection Profile

A network connection profile helps the SDK connect to the fabric network by providing all required information to operate with a fabric network, including:

* Client credentials file location;
* Service endpoints for peer, orderer and ca;
The [network.json](https://github.com/hyperledger/fabric-sdk-py/blob/main/test/fixtures/network.json) is an example, please modify the content accordingly.

The user key and cert can be passed to the SDK via the connection profile in three different ways.

| config_parameter | description | when to use |
|------------------|-------------|-------------|
| `"cert": {"pem": "base64 encoded cert"}` | The cert or key can be passed in a base64 encoded fashion via the `cert` parameter. | Good for testing and debugging. Should not be used for productive user-cases. |
| `"private_key": {"path": "/path/to/the/private_key"}` | The path to the cert or can be passed via the `path` parameter. | Standard way for key and cert parameters. |
| `"cert": "path/to/the/cert"` | The path can be passed directly without an additional `path` attribute. | Same as above, necessary to maintain backwards compatibility.

Now you can use the Python SDK to work with the fabric network!

## 1. Get Credentials

### 1.1 Load the Connection Profile

Load all network information from the profile, and check the resources.

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")

print(cli.organizations)  # orgs in the network
print(cli.peers)  # peers in the network
print(cli.orderers)  # orderers in the network
print(cli.CAs)  # ca nodes in the network
```

### 1.2 Prepare User Id (Optionally)

The SDK needs the credential files as a valid network user.

Typically there are two ways: using cryptogen or using Fabric-CA. That will depend on how your network boots up with.

#### 1.2.1 Using Local Credentials

The SDK will load the valid credentials from local path (the credential files must be put there in advance).

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user(org_name='org1.example.com', name='Admin') # get the admin user from local path
```

#### 1.2.2 Get Credentials from Fabric CA

Here demos how to interact with Fabric CA.

* Enroll into Fabric CA with admin role;
* Register a user `user1`;
* Enroll with the new user `user1` and get local credential;
* Re-enroll the `user1`;
* Revoke the `user1`.

To use CA, a CA server must be started. For example,

```bash
$ docker-compose -f test/fixtures/ca/docker-compose.yml up
```

```python
from hfc.fabric_ca.caservice import ca_service

casvc = ca_service(target="http://127.0.0.1:7054")
adminEnrollment = casvc.enroll("admin", "adminpw") # now local will have the admin enrollment
secret = adminEnrollment.register("user1") # register a user to ca
user1Enrollment = casvc.enroll("user1", secret) # now local will have the user enrollment
user1ReEnrollment = casvc.reenroll(user1Enrollment) # now local will have the user reenrolled object
RevokedCerts, CRL = adminEnrollment.revoke("user1") # revoke the user if you need
```

You can also use the new identity management system:

```python
from hfc.fabric_ca.caservice import ca_service

casvc = ca_service(target="http://127.0.0.1:7054")
identityService = casvc.newIdentityService()

admin = casvc.enroll("admin", "adminpw") # now local will have the admin user
secret = identityService.create(admin, 'foo') # create user foo
res = identityService.getOne('foo', admin) # get user foo
res = identityService.getAll(admin) # get all users
res = identityService.update('foo', admin, maxEnrollments=3, affiliation='.', enrollmentSecret='bar') # update user foo
res = identityService.delete('foo', admin) # delete user foo
```

You can also store the newly created credentials in the FileSystemWallet:

```python
from hfc.fabric_ca.caservice import ca_service
from hfc.fabric_network import wallet

casvc = ca_service(target="http://127.0.0.1:7054")
adminEnrollment = casvc.enroll("admin", "adminpw") # now local will have the admin enrollment
secret = adminEnrollment.register("user1") # register a user to ca
user1Enrollment = casvc.enroll("user1", secret) # now local will have the user enrollment
new_wallet = wallet.FileSystenWallet() # Creates default wallet at ./tmp/hfc-kvs
user_identity = wallet.Identity("user1", user1Enrollment) # Creates a new Identity of the enrolled user
user_identity.CreateIdentity(new_wallet) # Stores this identity in the FileSystemWallet
user1 = new_wallet.create_user("user1", "Org1", "Org1MSP") # Returns an instance of the user object with the newly created credentials
```

You can also store the newly created credentials in the InMemoryWallet:

```python
from hfc.fabric_ca.caservice import ca_service
from hfc.fabric_network import inmemorywallet

casvc = ca_service(target="http://127.0.0.1:7054")
adminEnrollment = casvc.enroll("admin", "adminpw") # now local will have the admin enrollment
secret = adminEnrollment.register("user1") # register a user to ca
user1Enrollment = casvc.enroll("user1", secret) # now local will have the user enrollment
new_wallet = inmemorywallet.InMemoryWallet() # Creates a new instance of the class InMemoryWallet
new_wallet.put("user1", user1Enrollment) # Saves the credentials of 'user1' in the wallet
```

## 2. Operate Channels with Fabric Network


### 2.1 Create a new channel and join it

Use SDK to create a new channel and let peers join it.

```python
import asyncio
from hfc.fabric import Client

loop = asyncio.get_event_loop()

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user(org_name='org1.example.com', name='Admin')

# Create a New Channel, the response should be true if succeed
response = loop.run_until_complete(cli.channel_create(
            orderer='orderer.example.com',
            channel_name='businesschannel',
            requestor=org1_admin,
            config_yaml='test/fixtures/e2e_cli/',
            channel_profile='TwoOrgsChannel'
            ))
print(response == True)

# Join Peers into Channel, the response should be true if succeed
orderer_admin = cli.get_user(org_name='orderer.example.com', name='Admin')
responses = loop.run_until_complete(cli.channel_join(
               requestor=org1_admin,
               channel_name='businesschannel',
               peers=['peer0.org1.example.com',
                      'peer1.org1.example.com'],
               orderer='orderer.example.com'
               ))
print(len(responses) == 2)


# Join Peers from a different MSP into Channel
org2_admin = cli.get_user(org_name='org2.example.com', name='Admin')

# For operations on peers from org2.example.com, org2_admin is required as requestor
responses = loop.run_until_complete(cli.channel_join(
               requestor=org2_admin,
               channel_name='businesschannel',
               peers=['peer0.org2.example.com',
                      'peer1.org2.example.com'],
               orderer='orderer.example.com'
               ))
print(len(responses) == 2)
```

### 2.2 Update the Channel Configuration

```python
import asyncio
from hfc.fabric import Client

loop = asyncio.get_event_loop()

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user(org_name='org1.example.com', name='Admin')

config_tx_file = './configtx.yaml'

orderer_admin = cli.get_user(org_name='orderer.example.com', name='Admin')
loop.run_until_complete(cli.channel_update(
        orderer='orderer.example.com',
        channel_name='businesschannel',
        requestor=orderer_admin,
        config_tx=config_tx_file))
```

## 3. Operate Chaincodes with Fabric Network

Use the SDK to install, instantiate and invoke chaincode.

```python
import asyncio
from hfc.fabric import Client

loop = asyncio.get_event_loop()

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

# Make the client know there is a channel in the network
cli.new_channel('businesschannel')

# Install Example Chaincode to Peers
# GOPATH setting is only needed to use the example chaincode inside sdk
import os
gopath_bak = os.environ.get('GOPATH', '')
gopath = os.path.normpath(os.path.join(
                      os.path.dirname(os.path.realpath('__file__')),
                      'test/fixtures/chaincode'
                     ))
os.environ['GOPATH'] = os.path.abspath(gopath)

# The response should be true if succeed
responses = loop.run_until_complete(cli.chaincode_install(
               requestor=org1_admin,
               peers=['peer0.org1.example.com',
                      'peer1.org1.example.com'],
               cc_path='github.com/example_cc',
               cc_name='example_cc',
               cc_version='v1.0'
               ))

# Instantiate Chaincode in Channel, the response should be true if succeed
args = ['a', '200', 'b', '300']

# policy, see https://hyperledger-fabric.readthedocs.io/en/release-1.4/endorsement-policies.html
policy = {
    'identities': [
        {'role': {'name': 'member', 'mspId': 'Org1MSP'}},
    ],
    'policy': {
        '1-of': [
            {'signed-by': 0},
        ]
    }
}
response = loop.run_until_complete(cli.chaincode_instantiate(
               requestor=org1_admin,
               channel_name='businesschannel',
               peers=['peer0.org1.example.com'],
               args=args,
               cc_name='example_cc',
               cc_version='v1.0',
               cc_endorsement_policy=policy, # optional, but recommended
               collections_config=None, # optional, for private data policy
               transient_map=None, # optional, for private data
               wait_for_event=True # optional, for being sure chaincode is instantiated
               ))

# Invoke a chaincode
args = ['a', 'b', '100']
# The response should be true if succeed
response = loop.run_until_complete(cli.chaincode_invoke(
               requestor=org1_admin,
               channel_name='businesschannel',
               peers=['peer0.org1.example.com'],
               args=args,
               cc_name='example_cc',
               transient_map=None, # optional, for private data
               wait_for_event=True, # for being sure chaincode invocation has been commited in the ledger, default is on tx event
               #cc_pattern='^invoked*' # if you want to wait for chaincode event and you have a `stub.SetEvent("invoked", value)` in your chaincode
               ))

# Query a chaincode
args = ['b']
# The response should be true if succeed
response = loop.run_until_complete(cli.chaincode_query(
               requestor=org1_admin,
               channel_name='businesschannel',
               peers=['peer0.org1.example.com'],
               args=args,
               cc_name='example_cc'
               ))

# Upgrade a chaincode
# policy, see https://hyperledger-fabric.readthedocs.io/en/release-1.4/endorsement-policies.html
policy = {
    'identities': [
        {'role': {'name': 'member', 'mspId': 'Org1MSP'}},
        {'role': {'name': 'admin', 'mspId': 'Org1MSP'}},
    ],
    'policy': {
        '1-of': [
            {'signed-by': 0}, {'signed-by': 1},
        ]
    }
}
response = loop.run_until_complete(cli.chaincode_upgrade(
               requestor=org1_admin,
               channel_name='businesschannel',
               peers=['peer0.org1.example.com'],
               args=args,
               cc_name='example_cc',
               cc_version='v1.0',
               cc_endorsement_policy=policy, # optional, but recommended
               collections_config=None, # optional, for private data policy
               transient_map=None, # optional, for private data
               wait_for_event=True # optional, for being sure chaincode is upgraded
               ))               

```

You can also invoke and query the chaincode through the Gateway
This has to be done after installing and instantiating the chaincode

```python
import asyncio
from hfc.fabric_network.gateway import Gateway
from hfc.fabric_network.network import Network
from hfc.fabric_network.contract import Contract
from hfc.fabric import Client

loop = asyncio.get_event_loop()

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user(org_name='org1.example.com', name='Admin')

new_gateway = Gateway() # Creates a new gateway instance
options = {'wallet': ''}
response = loop.run_until_complete(new_gateway.connect('test/fixtures/network.json', options))
new_network = loop.run_until_complete(new_gateway.get_network('businesschannel', org1_admin))
new_contract = new_network.get_contract('example_cc')
response = loop.run_until_complete(new_contract.submit_transaction('businesschannel', ['a', 'b', '100'], org1_admin))
response  = loop.run_until_complete(new_contract.evaluate_transaction('businesschannel', ['b'], org1_admin))

```

## 4. Query Informations

By default, `query` methods returns a decoded response.

If you need to get the raw response from the ledger you can add `decode=False` param.

### 4.1 Basic Usage

```python
import asyncio
from hfc.fabric import Client

loop = asyncio.get_event_loop()
cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

# Query Peer installed chaincodes, make sure the chaincode is installed
response = loop.run_until_complete(cli.query_installed_chaincodes(
               requestor=org1_admin,
               peers=['peer0.org1.example.com'],
               decode=True
               ))

"""
# An example response:

chaincodes {
  name: "example_cc"
  version: "v1.0"
  path: "github.com/example_cc"
  id: "\374\361\027j(\332\225\367\253\030\242\303U&\356\326\241\2003|\033\266:\314\250\032\254\221L#\006G"
}
"""

# Query Peer Joined channel
response = loop.run_until_complete(cli.query_channels(
               requestor=org1_admin,
               peers=['peer0.org1.example.com'],
               decode=True
               ))

"""
# An example response:

channels {
  channel_id: "businesschannel"
}
"""
```

### 4.2 Query Block by block hash & transaction id

```python
import asyncio
from hfc.fabric import Client

loop = asyncio.get_event_loop()
cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

# first get the hash by calling 'query_info'
response = loop.run_until_complete(cli.query_info(
               requestor=org1_admin,
               channel_name='businesschannel',
               peers=['peer0.org1.example.com'],
               decode=True
               ))

"""
# An example response:

height: 3
currentBlockHash: "\\\255\317\341$\"\371\242aP\030u\325~\263!\352G\014\007\353\353\247\235<\353\020\026\345\254\252r"
previousBlockHash: "\324\214\275z\301)\351\224 \225\306\"\250jBMa\3432r\035\023\310\250\017w\013\303!f\340\272"
"""

test_hash = response.currentBlockHash

response = loop.run_until_complete(cli.query_block_by_hash(
               requestor=org1_admin,
               channel_name='businesschannel',
               peers=['peer0.org1.example.com'],
               block_hash=test_hash,
               decode=True
               ))

tx_id = response.get('data').get('data')[0].get(
    'payload').get('header').get(
    'channel_header').get('tx_id')

response = loop.run_until_complete(cli.query_block_by_txid(
               requestor=org1_admin,
               channel_name='businesschannel',
               peers=['peer0.org1.example.com'],
               tx_id=tx_id,
               decode=True
               ))
```

### 4.3 Query Block, Transaction and Instantiated Chaincodes

```python
import asyncio
from hfc.fabric import Client

loop = asyncio.get_event_loop()
cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

# Query Block by block number
response = loop.run_until_complete(cli.query_block(
               requestor=org1_admin,
               channel_name='businesschannel',
               peers=['peer0.org1.example.com'],
               block_number='1',
               decode=True
               ))

# Query Transaction by tx id
# example txid of instantiated chaincode transaction
response = loop.run_until_complete(cli.query_transaction(
               requestor=org1_admin,
               channel_name='businesschannel',
               peers=['peer0.org1.example.com'],
               tx_id=tx_id, # tx_id same at 4.2
               decode=True
               ))

# Query Instantiated Chaincodes
response = loop.run_until_complete(cli.query_instantiated_chaincodes(
               requestor=org1_admin,
               channel_name='businesschannel',
               peers=['peer0.org1.example.com'],
               decode=True
               ))
```

### 4.4 Get channel configuration

```python
import asyncio
from hfc.fabric import Client

loop = asyncio.get_event_loop()
cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

# Get channel config
response = loop.run_until_complete(cli.get_channel_config(
               requestor=org1_admin,
               channel_name='businesschannel',
               peers=['peer0.org1.example.com'],
               decode=True
               ))
```


### 4.5 Use channel discovery

```python
import asyncio
from hfc.fabric import Client

loop = asyncio.get_event_loop()
cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

# Get config from local channel discovery
response = loop.run_until_complete(cli.query_peers(
               requestor=org1_admin,
               peer='peer0.org1.example.com',
               channel='businesschannel',
               local=True,
               decode=True
               ))

# Get config from channel discovery over the network
response = loop.run_until_complete(cli.query_peers(
               requestor=org1_admin,
               peer='peer0.org1.example.com',
               channel='businesschannel',
               local=False,
               decode=True
               ))
```


## 5. Usage of Channel Event Hub
In this section, we assume a channel named "business" channel is created and no chaincode is installed.
```python
import asyncio
from hfc.fabric import Client

loop = asyncio.get_event_loop()

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

# Make the client know there is a channel in the network
cli.new_channel('businesschannel')

# Install Example Chaincode to Peers
# GOPATH setting is only needed to use the example chaincode inside sdk
import os
gopath_bak = os.environ.get('GOPATH', '')
gopath = os.path.normpath(os.path.join(
                      os.path.dirname(os.path.realpath('__file__')),
                      'test/fixtures/chaincode'
                     ))
os.environ['GOPATH'] = os.path.abspath(gopath)

# Chaincode information
CC_PATH = 'github.com/example_cc_with_event'
CC_NAME = 'example_cc_with_event'
CC_VERSION = 'v1.0'
peer = cli.get_peer('peer0.org1.example.com')

# The response should be true if succeed
responses = loop.run_until_complete(cli.chaincode_install(
               requestor=org1_admin,
               peers=['peer0.org1.example.com',
                      'peer1.org1.example.com'],
               cc_path=CC_PATH,
               cc_name=CC_NAME,
               cc_version='v1.0'
               ))

# Instantiate the installed chaincode
args = ['a', '200', 'b', '300']

# policy, see https://hyperledger-fabric.readthedocs.io/en/release-1.4/endorsement-policies.html
policy = {
    'identities': [
        {'role': {'name': 'member', 'mspId': 'Org1MSP'}},
    ],
    'policy': {
        '1-of': [
            {'signed-by': 0},
        ]
    }
}

response = loop.run_until_complete(cli.chaincode_instantiate(
               requestor=org1_admin,
               channel_name='businesschannel',
               peers=['peer0.org1.example.com'],
               args=args,
               cc_name=CC_NAME,
               cc_version=CC_VERSION,
               cc_endorsement_policy=policy, # optional, but recommended
               collections_config=None, # optional, for private data policy
               transient_map=None, # optional, for private data
               wait_for_event=True # optional, for being sure chaincode is instantiated
               ))

def getBlocks(blocks):
    # On event complition the block is appended to the list of blocks
    def onEvent(block):
        blocks.append(block)
    # Returns an instance of the onEvent function
    return onEvent

blocks = [] # empty list

channel = cli.get_channel('businesschannel')
channel_event_hub = channel.newChannelEventHub(peer, org1_admin)
channel_event_hub.registerBlockEvent(start=0, onEvent=getBlocks(blocks))

stream = channel_event_hub.connect()
print(blocks)
```


## License <a name="license"></a>

<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br />This document is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.
