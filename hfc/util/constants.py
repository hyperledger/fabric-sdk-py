DEFAULT_PEER_GRPC_ADDR = 'localhost:7051'

TRANSACTION_TYPES = ['deploy', 'invoke']

dockerfile_contents = \
"""
from hyperledger/fabric-ccenv
COPY . $GOPATH/src/build-chaincode/
WORKDIR $GOPATH

RUN go install build-chaincode && mv $GOPATH/bin/build-chaincode $GOPATH/bin/{}
"""