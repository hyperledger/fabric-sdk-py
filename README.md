# Fabric-SDK-Py

**Note:** This is a **read-only mirror** of the formal [Gerrit](https://gerrit.hyperledger.org/r/#/admin/projects/fabric-sdk-py) repository, where active development is ongoing.

Fabric-SDK-Py is an implementation of the Hyperledger fabric SDK in Python.

## Incubation Notice

This project is a Hyperledger project in _Incubation_. It was proposed to the community and documented [here](https://docs.google.com/document/d/1N-KbwlFb7Oo_pTG2NjjLTqwlhqp_kjyv5fco7VH8WrE/), and was approved by [Hyperledger TSC at 2016-09-08](http://lists.hyperledger.org/pipermail/hyperledger-tsc/2016-September/000292.html). Information on what _Incubation_ entails can be found in the [Hyperledger Project Lifecycle document](https://goo.gl/4edNRc).

## Bug, Question and Code Contributions
Welcome for any kind of contribution, including bugs, questions and documentation!

Please see [How to Contribution](docs/CONTRIBUTING.md).

# Coding Style

We're following [pep8 style guide](https://www.python.org/dev/peps/pep-0008/) and [Google style](https://google.github.io/styleguide/pyguide.html), please see [coding style](docs/code_style.md)

## Pre-requisite

The SDK requires the `python-dev` and `libssl-dev` pkgs, so please make sure it's already installed.

Run the following cmd according to ur OS type.

| OS | command |
| -- | ---------- |
| Ubuntu/Debian | `sudo apt-get install python-dev python3-dev libssl-dev` |
| Redhat/CentOS | `sudo yum install python-devel python3-devel openssl-devel` |
| MacOS | `brew install python python3 openssl` |

More details to build the crypto lib, can be found at

* https://cryptography.io/en/latest/installation/#building-cryptography-on-linux
* https://cryptography.io/en/latest/installation/#building-cryptography-on-macos

## Testing
The following command will run the testing.

```sh
$ make check
```

## Generating Docker images
The following command will build a Docker image `hyperledger/fabric-sdk-py` with the fabric-sdk-py installed.

```sh
$ make image
```

Also, you can use docker-compose to start a cluster for testing, including fabric-peer, fabric-orderer, fabric-ca, and fabric-sdk-py containers.

```sh
$ docker-compose up -d
$ docker exec -it fabric-sdk-py bash
```

## Change Logs
See [Change Log](docs/change_log.md).

## Wiki

More information, please see the project [wiki](wiki.hyperledger.org/projects/fabric-sdk-py).

## License <a name="license"></a>
The Hyperledger Fabric-SDK-Py Project uses the [Apache License Version 2.0](LICENSE) software license.

## About Hyperledger Project

* [Hyperledger Project](https://www.hyperledger.org)
* [Hyperledger mailing lists and archives](http://lists.hyperledger.org/)
* [Hyperledger Chat](http://chat.hyperledger.org)
* [Hyperledger Wiki](https://github.com/hyperledger/hyperledger/wiki)
