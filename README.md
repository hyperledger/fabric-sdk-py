# Fabric-SDK-py

**Note:** This is a **read-only mirror** of the formal [Gerrit](https://gerrit.hyperledger.org/r/#/admin/projects/fabric-sdk-py) repository, where active development is ongoing.

Fabric-SDK-py is an implementation of the Hyperledger fabric SDK in Python.

## Incubation Notice

This project is a Hyperledger project in _Incubation_. It was proposed to the community and documented [here](https://docs.google.com/document/d/1N-KbwlFb7Oo_pTG2NjjLTqwlhqp_kjyv5fco7VH8WrE/), and was approved by [Hyperledger TSC at 2016-09-08](http://lists.hyperledger.org/pipermail/hyperledger-tsc/2016-September/000292.html). Information on what _Incubation_ entails can be found in the [Hyperledger Project Lifecycle document](https://goo.gl/4edNRc).

## Bug, Question and Code Contributions
Welcome for any kind of contribution!

Please see [How to Contribution](docs/CONTRIBUTING.md).

## Python Coding Standards

In order to make the code more maintainable, and helps developers understand code in reviews, we have a set of style guidelines for clarity.

* Please read [pep8 style guide](https://www.python.org/dev/peps/pep-0008/) before you try to contribute any code. The guidelines gives some basic coding conventions, including:
    - Code lay-out
    - String Quotes
    - Naming Conventions
    - Comments

* Some general guidelines you should follow like following when you write SDK code:
    - Use only UNIX style newlines (\n), not Windows style (\r\n)
    - It is preferred to wrap long lines in parentheses and not a backslash for line continuation.
    - Do not import more than one module per line
    - Docstrings should not start with a space.
    - Multi line docstrings should end on a new line.
    - Multi line docstrings should start without a leading new line.
    - Multi line docstrings should start with a one line summary followed by an empty line.

* For every api which will be used by our client, the api Docstrings are mandatory. The Google style guide contains an excellent Python style guide, we should follow. For example:

```
def square_root(n):
    """Calculate the square root of a number.

    Args:
        n: the number to get the square root of.
    Returns:
        the square root of n.
    Raises:
        TypeError: if n is not a number.
        ValueError: if n is negative.

    """
    pass
```

To extend this style to also include type information in the arguments, for example:

```
def add_value(self, value):
    """Add a new value.

    Args:
        value (str): the value to add.
    """
    pass
```

## Meeting

Weekly scrum meeting will be held at Slack channel [#fabric-sdk-py](https://hyperledgerproject.slack.com/messages/fabric-sdk-dev/) at 03:00 UTC every Friday.

## Testing
The following command will run the testing.

```sh
$ make check
```

## Generating Docker images
The following command will build a Docker image `hyperledger/fabric-sdk-py` with the fabric-sdk-py installed.

```sh
$ make docker
```

Also, you can use docker-compose to start a cluster for testing, including a fabric peer, an orderer, and an sdk-py container. **Note:** For the orderer, after you pull the hyperledger/fabric-peer image, you need to retag it to hyperledger/fabric-orderer.

```sh
$ docker-compose up -d
$ docker exec -it fabric-sdk-py tox
```

## Change Logs
See [Change Log](docs/change_log.md).

## About Hyperledger Project

* [Hyperledger Project](https://www.hyperledger.org)
* [Hyperledger mailing lists and archives](http://lists.hyperledger.org/)
* [Hyperledger Slack](http://hyperledgerproject.slack.com) - if you need an invitation, try our [Slack inviter](https://slack.hyperledger.org)
* [Hyperledger Wiki](https://github.com/hyperledger/hyperledger/wiki)

## License <a name="license"></a>
The Hyperledger Project uses the [Apache License Version 2.0](LICENSE) software license.
