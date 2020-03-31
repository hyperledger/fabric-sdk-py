Welcome to fabric-sdk-py's documentation!
=========================================

## Fabric-sdk-py

Fabric-SDK-Py is the Python 3.x implementation of Hyperledger Fabric SDK! Currently, it mainly supports Fabric 1.4.x version.

## Pre-requisite for he fabric-sdk-py

The SDK requires the `Python3` and `Libssl` pkgs. Run the following cmd to install the pre-requisites if you do not have:

| OS            | Command                                                     |
| :-----------: | :---------------------------------------------------------: |
| Ubuntu/Debian | `sudo apt-get install python-dev python3-dev libssl-dev`    |
| Redhat/CentOS | `sudo yum install python-devel python3-devel openssl-devel` |
| MacOS         | `brew install python python3 openssl`                       |

## Creating the Virtual Evironment

Virtual environment helps provide a clean environment for makin the changes and test them locally, Also we suggest suggest to use it to test.

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
We welcome any kind of contribution, You can see open issues, requests, code components and also can report your issue (here)[https://jira.hyperledger.org/projects/FABP/issues/FABP-255?filter=allopenissues]

## Ask Question
We are are the opensource community and we always welcome your questions.
Feel free to ask any question on our community (here)[https://chat.hyperledger.org/channel/fabric-sdk-py]

## Get started and read our Documentation
You can find our documentation (here)[https://github.com/hyperledger/fabric-sdk-py/tree/master/docs]

## Feel free to contribute
Let's get started and contribute to Fabric-sdk-py. you can start (here)[https://github.com/hyperledger/fabric-sdk-py/blob/master/CONTRIBUTING.md]

## Some Important Link
* (Fabric SDK Python Wiki)[https://wiki.hyperledger.org/display/fabric/Hyperledger+Fabric+SDK+Py]
* (Hyperledger Project)[https://www.hyperledger.org/]
* (Hyperledger mailing lists)[https://lists.hyperledger.org/g/main]

## License
The Hyperledger Fabric-SDK-Py software uses the (Apache License Version 2.0)[https://github.com/hyperledger/fabric-sdk-py/blob/master/LICENSE] software license.
This document is licensed under a (Creative Commons Attribution 4.0 International License.)[https://creativecommons.org/licenses/by/4.0/]

## Package Reference

* [Tutorial](tutorial.md)
* [Release Note](release_note.md)
* [Code Style](code_style.md)
* [Contributing](CONTRIBUTING.md)