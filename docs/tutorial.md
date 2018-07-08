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

## Interaction with Fabric Network

After load the configuration, SDK can operate with the network.

### Create a New Channel

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

# The response should be true if succeed
response = cli.channel_create(
            'orderer.example.com',     # orderer_name
            'businesschannel',         # channel_name
            org1_admin,                # requester
            'test/fixtures/e2e_cli/',  # config_yaml
            'TwoOrgsChannel'           # channel_profile
                             )
```

### Join Peers into Channel

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

# The response should be true if succeed
response = cli.channel_join(
               org1_admin,                 #requester
               'businesschannel',          #channel_name
               ['peer0.org1.example.com',
                'peer1.org1.example.com'], #peer_names
               'orderer.example.com'       #orderer_name
                           )
```

### Install Chaincode to Peers

```python
from hfc.fabric import Client

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')

# The response should be true if succeed
response = cli.chaincode_install(
               org1_admin,                 #requestor
               ['peer0.org1.example.com'], #peer_names
               'github.com/example_cc',    #cc_path
               'example_cc',               #cc_name
               'v1.0'                      #cc_version
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
               org1_admin,                 #requestor
               ['peer0.org1.example.com'], #peer_names
               args,                       #args
               'example_cc',               #cc_name
               'v1.0'                      #cc_version
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
               org1_admin,                 #requestor
               ['peer0.org1.example.com'], #peer_names
               args,                       #args
               'example_cc',               #cc_name
               'v1.0'                      #cc_version
                               )
```


## License <a name="license"></a>

<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br />This document is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.
