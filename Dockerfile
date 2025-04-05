# SPDX-License-Identifier: Apache-2.0
#
FROM python:3.12
MAINTAINER fabric-sdk-py "https://wiki.hyperledger.org/projects/fabric-sdk-py.md"

COPY . /fabric-sdk-py

WORKDIR /fabric-sdk-py

RUN pip install tox pytest setuptools \
    && python setup.py install

CMD ["bash", "-c", "while true; do sleep 1000; done"]