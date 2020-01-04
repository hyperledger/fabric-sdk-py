# Fabric-SDK-Py

Fabric-SDK-Py is an implementation of the Hyperledger fabric SDK with Python 3.x!

## Pre-requisite

The SDK requires the `Python3` and `Libssl` pkgs.

Run the following cmd to install the pre-requisites if you do not have:

| OS | command |
| -- | ---------- |
| Ubuntu/Debian | `sudo apt-get install python-dev python3-dev libssl-dev` |
| Redhat/CentOS | `sudo yum install python-devel python3-devel openssl-devel` |
| MacOS | `brew install python python3 openssl` |

More details to build the crypto lib, can be found at

* https://cryptography.io/en/latest/installation/#building-cryptography-on-linux
* https://cryptography.io/en/latest/installation/#building-cryptography-on-macos

## Tutorial

See [Tutorial](docs/tutorial.md) to get familiar with the major SDK APIs.

## Quick Testing

### Use Virtual Env

[virtualenv](https://virtualenv.pypa.io) helps provide a clean environment, suggest to use it to test.

```sh
$ pip3 install virtualenv # install the virtualenv tool if not installed
$ make venv  # create a virtual env
$ source venv/bin/activate
$ # Do the testing here
$ deactivate  # deactive the virtual env
$ make clean # clean the temporary files
```

### Run Integration Testing
The following command will run the testing.
```sh
$ make check # Check environment and run tests
$ make test # Only run test cases
$ tox -e py30 -- test/integration/ca_test.py  # Run specified test case
```

## Generating Docker images
The following command will build the Docker image `hyperledger/fabric-sdk-py`.

```sh
$ make image
```

## Regenerating protos

Make sure you have `grpcio-tools` installed (`pip install grpcio-tools`)
```sh
make proto
```

## Change Logs
See [Change Log](CHANGELOG.md) for the commit logs. Run `make changelog` to update the changelog before new release.

## Other Important Links

* [Fabric SDK Python Wiki](wiki.hyperledger.org/projects/fabric-sdk-py)
* [Hyperledger Project](https://www.hyperledger.org)
* [Hyperledger mailing lists](http://lists.hyperledger.org/)

## Bug, Question and Code Contributions
Welcome for any kind of contributions, e.g., [bugs](https://jira.hyperledger.org/projects/FABP), [questions](https://chat.hyperledger.org/channel/fabric-sdk-py) and [documentation](https://github.com/hyperledger/fabric-sdk-py/tree/master/docs)!

Recommend to read [How to Contribution](CONTRIBUTING.md) before taking action.

## Incubation Notice

This project is in [_Incubation_](https://goo.gl/4edNRc) now, and was [proposed](https://docs.google.com/document/d/1N-KbwlFb7Oo_pTG2NjjLTqwlhqp_kjyv5fco7VH8WrE/) and [approved](http://lists.hyperledger.org/pipermail/hyperledger-tsc/2016-September/000292.html) by Hyperledger TSC at Sep 08, 2016.

## License <a name="license"></a>
The Hyperledger Fabric-SDK-Py software uses the [Apache License Version 2.0](LICENSE) software license.

<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br />This document is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.
