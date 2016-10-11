FROM python:3.5

RUN git clone https://github.com/hyperledger/fabric-sdk-py \
    && cd fabric-sdk-py \
    && pip install tox pytest \
    && python setup.py install

WORKDIR /fabric-sdk-py

CMD while true; do sleep 1000; done