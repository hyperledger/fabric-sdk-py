# Tutorial of using Fabric SDK

**Notice: The tutorial is still in-progress.**

## Pre-requisites

### Install Fabric SDK

```bash
$ git clone https://github.com/hyperledger/fabric-sdk-py.git
$ cd fabric-sdk-py
$ python setup.py install
```

After installation, you can optionally verify the installation.

```bash
$ python
>>> import hfc
>>> print(hfc.VERSION)
0.0.1
```

### Start a Fabric Network

SDK needs a targeted fabric network to operate with, if there is not a running one, need to start a network manually.

TODO: Need more details/script to quickly start a fabric network.

### Create Connection Profile

A network connection profile will include all information that SDK requires to operate with a fabric network, including:

* Service endpoints for peer, orderer, ca;
* Credentials for identities that clients may act as;

e.g., `network1.json`.

## Load Configurations

SDK can load all network information from the profile, and check the resources in the network.

```python
# TODO: update code
from hfc.fabric.client import Client

cli = Client(net_profile="test/fixtures/network.json")

cli.organizations()  # orgs in the network
cli.peers()  # peers in the network
cli.orderers()  # orderers in the network
cli.CAs()  # ca nodes in the network
```

## Interaction with Fabric Network

After load the configuration, SDK can operate with the network.

### Create a New Channel
```python
# TODO: update code
from hfc.fabric.client import Client

cli = Client(net_profile="test/fixtures/network.json")
org1_admin = cli.get_user('org1.example.com', 'Admin')
response = cli.create_channel('orderer.example.com', 'businesschannel', org1_admin, 'test/fixtures/e2e_cli/channel-artifacts/channel.tx')
```

### Join Peers into Channel

### Install Chaincode to Peers

### Instantiate Chaincode in Channel

### Invoke a Chaincode

## License <a name="license"></a>

<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br />This document is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.
