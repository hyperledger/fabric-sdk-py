Welcome to fabric-sdk-py's documentation!
=========================================

## Fabric-SDK-Py

Fabric-SDK-Py is the Python 3.x implementation of Hyperledger Fabric SDK. Currently, it mainly supports Fabric 1.4.x version.

## Pre-requisites
The SDK requires `Python3` and `Libssl` packages. Run the following commands to install the pre-requisites:

| OS            | Command                                                     |
| :-----------: | :---------------------------------------------------------: |
| Ubuntu/Debian | `sudo apt-get install python-dev python3-dev libssl-dev`    |
| Redhat/CentOS | `sudo yum install python-devel python3-devel openssl-devel` |
| MacOS         | `brew install python python3 openssl`                       |

## Creating a Virtual Evironment
Virtual environment helps providing a clean environment for making changes and testing them locally. Also, it is highly suggested for testing purposes.

```
$ pip3 install virtualenv # install the virtualenv tool if not installed
$ make venv  # create a virtual env
$ source venv/bin/activate
$ # Do the testing here
$ deactivate  # deactive the virtual env
$ make clean # clean the temporary files
```

## Run Integration Testing

The following command will run the testing.

```
$ make check # Check environment and run tests
$ make test # Only run test cases
$ tox -e py3 -- test/integration/ca_test.py  # Run specified test case
```

## Reporting Bug
We welcome any kind of contribution, You can see open issues, requests, code components and also report an issue [here](https://jira.hyperledger.org/projects/FABP/issues/FABP-255?filter=allopenissues).

## Ask Questions
We are an opensource community and always welcome your questions.
Feel free to ask any question on our community [here](https://chat.hyperledger.org/channel/fabric-sdk-py).

## Get started and read our Documentation
You can find our documentation [here](https://github.com/hyperledger/fabric-sdk-py/tree/main/docs).

## Feel free to contribute
Let's get started and contribute to Fabric-SDK-Py! You can start [here](https://github.com/hyperledger/fabric-sdk-py/blob/main/CONTRIBUTING.md).

## Some Important Links
* [Fabric SDK Python Wiki](https://wiki.hyperledger.org/display/fabric/Hyperledger+Fabric+SDK+Py)
* [Hyperledger Project](https://www.hyperledger.org/)
* [Hyperledger mailing lists](https://lists.hyperledger.org/g/main)

## License
The Hyperledger Fabric-SDK-Py software uses the [Apache License Version 2.0](https://github.com/hyperledger/fabric-sdk-py/blob/main/LICENSE) software license.
This document is licensed under a [Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/).

## Package Reference

* [Tutorial](tutorial.md)
* [Release Note](release_note.md)
* [Code Style](code_style.md)
* [Contributing](CONTRIBUTING.md)
