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


## Package Reference

* [Tutorial](tutorial.md)
* [Release Note](release_note.md)
* [Code Style](code_style.md)
* [Contributing](CONTRIBUTING.md)