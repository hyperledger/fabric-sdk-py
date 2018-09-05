# Tutorial of using Fabric SDK

**Notice: The tutorial is still in-progress, and example code can be found at [e2e_test.py](test/integration/e2e_test.py).**

## 0. Pre-requisites

### 0.1. Install Fabric SDK

```bash
$ git clone https://github.com/hyperledger/fabric-sdk-py.git
$ cd fabric-sdk-py
$ make install
```

After installation, you can optionally verify the installation by checking the version number.

```bash
$ python
>>> import hfc
>>> print(hfc.VERSION)
0.7.0
```

### 0.2. Start a Fabric Network

To start an example fabric network you can simply run the following command:

```bash
$ docker pull hyperledger/fabric-peer:x86_64-1.0.0
$ docker pull hyperledger/fabric-orderer:x86_64-1.0.0
$ docker pull hyperledger/fabric-ca:x86_64-1.0.0
$ docker pull hyperledger/fabric-ccenv:x86_64-1.0.0
$ docker-compose -f test/fixtures/docker-compose-2orgs-4peers-tls.yaml up
```

Then you'll have a fabric network with topology of 3 organizations:
 * org1.example.com
   * peer0.org1.example.com
   * peer1.org1.example.com
 * org2.example.com
   * peer0.org2.example.com
   * peer1.org2.example.com
 * orderer.example.com
   * orderer.example.com

* Note: make sure `configtxgen` is in the 'PATH' and the version of `configtxgen` is 1.0.0
* Also, it is recmmended that you set logging level to DEBUG or INFO when you meet a problem

If you want to understand more details on starting up a fabric network, feel free to see the [Building Your First Network](https://hyperledger-fabric.readthedocs.io/en/latest/build_network.html) tutorial.

### 0.3. Create the Connection Profile

A network connection profile helps SDK connect to the fabric network by providing all required information to operate with a fabric network, including:

* Service endpoints for peer, orderer, ca;
* Credentials for identities that clients may act as;

For example, [network.json](test/fixtures/network.json).

## 1. Get Credentials

### 1.1 Load Connection Profile

SDK can load all network information from the profile, and check the resources in the network.

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")

cli.organizations  # orgs in the network
cli.peers  # peers in the network
cli.orderers  # orderers in the network
cli.CAs  # ca nodes in the network
```

### 1.2 Prepare User Id (Optionally)

SDK will try to get the credential of a valid network user first.

#### 1.2.2 There's user in profile, just get the credential

SDK will get valid credentials from fabric-ca.

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user(org_name='org1.example.com', name='Admin') # get the admin user from local path
```

#### 1.2.1 If no valid user exist yet, register and enroll from fabric-ca
SDK will login with default admin role and register a user.

```python
from hfc.fabric_ca import CAClient

cli = CAClient(server_addr="127.0.0.1:7050")
admin = cli.enroll(username="admin", password="pass") # now local will have the admin user
admin.register(username="user1", password="pass1", attributions={}) # register a user to ca
user1 = cli.enroll(username="user1", password="pass1") # now local will have the user
```

## 2. Operate Channels with Fabric Network

Use sdk to create a new channel and let peers join it.

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user(org_name='org1.example.com', name='Admin')

# Create a New Channel, the response should be true if succeed
response = cli.channel_create(
            orderer_name='orderer.example.com',
            channel_name='businesschannel',
            requestor=org1_admin,
            config_yaml='test/fixtures/e2e_cli/',
            channel_profile='TwoOrgsChannel'
            )
print(response==True)

# Join Peers into Channel, the response should be true if succeed
response = cli.channel_join(
               requestor=org1_admin,
               channel_name='businesschannel',
               peer_names=['peer0.org1.example.com',
                           'peer1.org1.example.com']
               orderer_name='orderer.example.com'
               )
print(response==True)


# Join Peers from a different MSP into Channel
org2_admin = cli.get_user(org_name='org2.example.com', name='Admin')

# For operations on peers from org2.example.com, org2_admin is required as requestor
response = cli.channel_join(
               requestor=org2_admin,
               channel_name='businesschannel',
               peer_names=['peer0.org2.example.com',
                           'peer1.org2.example.com']
               orderer_name='orderer.example.com'
               )
print(response==True)

```

## 3. Operate Chaincodes with Fabric Network

Use sdk to install, instantiate and invoke chaincode.

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

# Install Chaincode to Peers
# This is only needed if to use the example chaincode inside sdk
import os
gopath_bak = os.environ.get('GOPATH', '')
gopath = os.path.normpath(os.path.join(
                      os.path.dirname(os.path.realpath('__file__')),
                      'test/fixtures/chaincode'
                     ))
os.environ['GOPATH'] = os.path.abspath(gopath)

# The response should be true if succeed
response = cli.chaincode_install(
               requestor=org1_admin,
               peer_names=['peer0.org1.example.com',
                           'peer1.org1.example.com']
               cc_path='github.com/example_cc',
               cc_name='example_cc',
               cc_version='v1.0'
               )

# Instantiate Chaincode in Channel, the response should be true if succeed
args = ['a', '200', 'b', '300']
response = cli.chaincode_instantiate(
               requestor=org1_admin,
               channel_name='businesschannel',
               peer_names=['peer0.org1.example.com'],
               args=args,
               cc_name='example_cc',
               cc_version='v1.0'
               )

# Invoke a chaincode
args = ['a', 'b', '100']
# The response should be true if succeed
response = cli.chaincode_invoke(
               requestor=org1_admin,
               channel_name='businesschannel',
               peer_names=['peer0.org1.example.com'],
               args=args,
               cc_name='example_cc',
               cc_version='v1.0'
               )
```

### Query a Chaincode

TBD.

## 4. Query Informations

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

# Query Peer installed chaincodes, make sure the chaincode is installed
response = cli.query_installed_chaincodes(
               requestor=org1_admin,
               peer_names=['peer0.org1.example.com']
               )

"""
# An example response:

chaincodes {
  name: "example_cc"
  version: "1.0"
  path: "github.com/example_cc"
}
"""

# Query Peer Joined channel
response = cli.query_channels(
               requestor=org1_admin,
               peer_names=['peer0.org1.example.com']
               )

"""
# An example response:

channels {
  channel_id: "businesschannel"
}
"""

# Query Channel Info
response = cli.query_info(
               requestor=org1_admin,
               channel_name='businesschannel',
               peer_names=['peer0.org1.example.com']
               )

# Query Block by tx id
# example txid of instantiated chaincode transaction
response = cli.query_block_by_txid(
               requestor=org1_admin,
               channel_name='businesschannel',
               peer_names=['peer0.org1.example.com'],
               tx_id=cli.txid_for_test
                                  )
```

### Query Block by block hash

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

# first get the hash by calling 'query_info'
response = cli.query_info(
               requestor=org1_admin,
               channel_name='businesschannel',
               peer_names=['peer0.org1.example.com'],
                           )

test_hash = response.currentBlockHash

response = cli.query_block_by_hash(
               requestor=org1_admin,
               channel_name='businesschannel',
               peer_names=['peer0.org1.example.com'],
               block_hash=test_hash
                           )
```

### Query Block by block number

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

# Query Block by block number
response = cli.query_block(
               requestor=org1_admin,
               channel_name='businesschannel',
               peer_names=['peer0.org1.example.com'],
               block_number='1'
               )

# Query Transaction by tx id
# example txid of instantiated chaincode transaction
response = cli.query_transaction(
               requestor=org1_admin,
               channel_name='businesschannel',
               peer_names=['peer0.org1.example.com'],
               tx_id=cli.txid_for_test
               )

# Query Instantiated Chaincodes
response = cli.query_instantiated_chaincodes(
               requestor=org1_admin,
               channel_name='businesschannel',
               peer_names=['peer0.org1.example.com']
               )
```

## License <a name="license"></a>

<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br />This document is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.
