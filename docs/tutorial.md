# Tutorial of using Fabric SDK

**Notice: The tutorial is still in-progress, feel free to ask question in the rktchat channel. Code can be found at [e2e_test.py](test/integration/e2e_test.py).**


## Pre-requisites

### Install Fabric SDK

```bash
$ git clone https://github.com/hyperledger/fabric-sdk-py.git
$ cd fabric-sdk-py
$ make install
```

After installation, you can optionally verify the installation.

```bash
$ python
>>> import hfc
>>> print(hfc.VERSION)
0.7.0
```

### Start a Fabric Network

SDK needs a targeted fabric network to operate with, if there is not a running one, need to start a network manually.

To start a fabric network you can simple up the `docker-compose-2orgs-4peers-tls` under fixtures.

```bash
$ docker-compose -f test/fixtures/docker-compose-2orgs-4peers-tls.yaml up
```

Then you'll have 2 orgs (org1.example.com; org2.example.com) with 2 peers in each one and one orderer (orderer.example.com)

If you want to understand the fabric network and how to change the network configuration, feel free to follow the byfn tutorial, from [crypto-generator section](http://hyperledger-fabric.readthedocs.io/en/release/build_network.html#crypto-generator) to [start-the-network section](http://hyperledger-fabric.readthedocs.io/en/release/build_network.html#start-the-network).
service on the yaml file either.

### Create Connection Profile

A network connection profile will include all information that SDK requires to operate with a fabric network, including:

* Service endpoints for peer, orderer, ca;
* Credentials for identities that clients may act as;

e.g., `network1.json`.

## Load Configurations

SDK can load all network information from the profile, and check the resources in the network.

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")

cli.organizations  # orgs in the network
cli.peers  # peers in the network
cli.orderers  # orderers in the network
cli.CAs  # ca nodes in the network
```

## Prepare User Id (Optionally)

SDK will try to get the credential of a valid network user from fabric-sdk.


### If no valid user exist yet, register first
SDK will login with default admin role and register a user.

```python
from hfc.fabric_ca import Client

cli = Client(server_addr="127.0.0.1:7050")
admin = cli.enroll(username="admin", password="pass") # now local will have the admin user
```

### There's user, just get the credential
SDK will get valid credentials from fabric-ca.

```python
from hfc.fabric_ca import Client
cli = Client(server_addr="127.0.0.1:7050")
admin = cli.get_user(username="admin") # get the admin user from local path
admin.register(username="user1", password="pass1", attributions={}) # register a user to ca
user1 = cli.enroll(username="user1", password="pass1") # now local will have the user
```

## Interaction with Fabric Network

After load the configuration, SDK can operate with the network.

### Create a New Channel

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

# The response should be true if succeed
response = cli.channel_create(
            orderer_name='orderer.example.com',
            channel_name='businesschannel',
            requestor=org1_admin,
            config_yaml='test/fixtures/e2e_cli/',
            channel_profile='TwoOrgsChannel'
                             )
```

### Join Peers into Channel

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

# The response should be true if succeed
response = cli.channel_join(
               requestor=org1_admin,
               channel_name='businesschannel',
               peer_names=['peer0.org1.example.com',
                'peer1.org1.example.com'],
               orderer_name='orderer.example.com'
                           )
```

### Install Chaincode to Peers

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

# The response should be true if succeed
response = cli.chaincode_install(
               requestor=org1_admin,
               peer_names=['peer0.org1.example.com'],
               cc_path='github.com/example_cc',
               cc_name='example_cc',
               cc_version='v1.0'
                                )
```

### Instantiate Chaincode in Channel

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

# for chaincode instantiation
args = ['a', '200', 'b', '300']
# The response should be true if succeed
response = cli.chaincode_instantiate(
               requestor=org1_admin,
               channel_name='businesschannel',
               peer_names=['peer0.org1.example.com'],
               args=args,
               cc_name='example_cc',
               cc_version='v1.0'
                                    )
```

### Invoke a Chaincode

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

# for chaincode invoke
args = ['a', 'b', '100']
# The response should be true if succeed
response = cli.chaincode_invoke(
               requestor=org1_admin,
               channel_name='businesschannel',
               peer_names=['peer0.org1.example.com'],
               args=args,
               cc_name='example_cc',
               cc_version'v1.0'
                               )
```

### Query an installed chaincode

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

# make sure the chaincode is installed
response = cli.query_installed_cc(
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

```

### Query a channel

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

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

```

### Query Info

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

response = cli.query_info(
               requestor=org1_admin,
               channel_name='businesschannel',
               peer_names=['peer0.org1.example.com']
                          )
```

### Query Block by tx id

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

# example txid of instantiated chaincode transaction
response = cli.query_block_by_txid(
               requestor=org1_admin,
               channel_name='businesschannel',
               peer_names=['peer0.org1.example.com'],
               tx_id=cli.txid_for_test
                              )
```

### Query Block by block number

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

response = cli.query_block(
               requestor=org1_admin,
               channel_name='businesschannel',
               peer_names=['peer0.org1.example.com'],
               block_number='1'
                           )
```

### Query Transaction by tx id

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

# example txid of instantiated chaincode transaction
response = cli.query_transaction(
               requestor=org1_admin,
               channel_name='businesschannel',
               peer_names=['peer0.org1.example.com'],
               tx_id=cli.txid_for_test
                                )
```

### Query Instantiated Chaincodes

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

response = cli.query_instantiated_chaincodes(
               requestor=org1_admin,
               channel_name='businesschannel',
               peer_names=['peer0.org1.example.com']
                                            )
```

## License <a name="license"></a>

<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br />This document is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.
