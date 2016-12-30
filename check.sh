#!/bin/bash

# checking local version
echo "===Checking Docker and Docker-Compose version"
docker version
docker-compose -v

# clean env
echo "===Clean env..."
docker-compose -f test/docker-compose-test.yml stop
docker-compose -f test/docker-compose-test.yml kill
docker-compose -f test/docker-compose-test.yml rm -f

# start env and wait until services started
echo "===Setup env, will use official images when they're ready..."
docker pull yeasy/hyperledger-fabric-cop
docker pull yeasy/hyperledger-fabric-peer
docker pull yeasy/hyperledger-fabric-orderer
docker tag yeasy/hyperledger-fabric-cop:latest hyperledger/fabric-cop:latest
docker tag yeasy/hyperledger-fabric-peer:latest hyperledger/fabric-peer:latest
docker tag yeasy/hyperledger-fabric-orderer:latest hyperledger/fabric-order:latest

docker-compose -f test/docker-compose-test.yml up > ./docker-compose.log 2>&1 &
ret=$?

sleep 10

docker ps -a

if [ $ret -eq 0 ]; then
    # run tests
    echo "===Starting test..."
    #docker exec -i fabric-sdk-py make test
    make test
    ret=$?
fi

# clean env
echo "===Clean env after the testing..."
docker-compose -f test/docker-compose-test.yml stop
docker-compose -f test/docker-compose-test.yml kill
docker-compose -f test/docker-compose-test.yml rm -f

# show compose log for potential debug purpose
echo "===Show Docker-Compose log after the testing..."
cat ./docker-compose.log

exit $ret
