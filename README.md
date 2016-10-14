# Fabric-SDK-py

**Note:** This is a **read-only mirror** of the formal [Gerrit](https://gerrit.hyperledger.org/r/#/admin/projects/fabric-sdk-py) repository, where active development is ongoing.

Issue tracking is handled in [Jira](https://jira.hyperledger.org/secure/RapidBoard.jspa?rapidView=85).

Technical discussion is handled in [Slack](http://hyperledgerproject.slack.com) channel `#fabric-sdk-py`.

## Incubation Notice

This project is a Hyperledger project in _Incubation_. It was proposed to the community and documented [here](https://docs.google.com/document/d/1N-KbwlFb7Oo_pTG2NjjLTqwlhqp_kjyv5fco7VH8WrE/), and was approved by [Hyperledger TSC at 2016-09-08](http://lists.hyperledger.org/pipermail/hyperledger-tsc/2016-September/000292.html). Information on what _Incubation_ entails can be found in the [Hyperledger Project Lifecycle document](https://goo.gl/4edNRc).

## About

Fabric-SDK-py is an implementation of the Hyperledger fabric SDK in Python.

## Installation

For non-developers, the code can be cloned from [Github](https://github.com/hyperledger/fabric-sdk-py).

```sh
$ git clone https://github.com/hyperledger/fabric-sdk-py
```

## Contributing
We welcome contributions to the Hyperledger Project in many forms. There’s always plenty to do!

Full details of how to contribute to this project are documented [here](http://hyperledger-fabric.readthedocs.io/en/latest/CONTRIBUTING/).

For developers, please also see [How to Contribution](docs/contribution.md).

## Testing
The following command will build a Docker image with the fabric-sdk-py installed.

```sh
$ docker build -t hyperledger/fabric-sdk-py .
$ docker run -it hyperledger/fabric-sdk-py tox
```

Also, you can use docker-compose to start a cluster for testing, including a fabric peer, a membersrvc, and an sdk-py container.

```sh
$ docker-compose up -d
$ docker exec -it sdk-py tox
```

## Core Developers
| Name | GitHub | Gerrit | Email |
| ---- | ------ | ------ | ----- |
| Baohua Yang | yeasy | baohua | yangbaohua@gmail.com |
| Chen Kai    | grapebaba | grapebaba | 281165273@qq.com |
| Chang Chen  | | lafenicecc | ccchenbj@cn.ibm.com |
| Qiang Wang  | | qiang0723  | wqiang0723@gmail.com |
| Chuanjian Wang | | ckeyer | me@ckeyer.com |

## Change Logs
See [Change Log](docs/change_log.md).

## Community

* [Hyperledger Community](https://www.hyperledger.org/community)
* [Hyperledger mailing lists and archives](http://lists.hyperledger.org/)
* [Hyperledger Slack](http://hyperledgerproject.slack.com) - if you need an invitation, try our [Slack inviter](https://slack.hyperledger.org)
* [Hyperledger Wiki](https://github.com/hyperledger/hyperledger/wiki)
* [Hyperledger Code of Conduct](https://github.com/hyperledger/hyperledger/wiki/Hyperledger-Project-Code-of-Conduct)
* [Community Calendar](https://github.com/hyperledger/hyperledger/wiki/PublicMeetingCalendar)

## License <a name="license"></a>
The Hyperledger Project uses the [Apache License Version 2.0](LICENSE) software license.
