#!/bin/bash
set -x
# checking local version
echo "===Checking Docker and Docker-Compose version"
docker version
docker-compose -v

# pull fabric images
echo "===Pulling fabric images..."
docker pull yeasy/hyperledger-fabric-ca
docker pull yeasy/hyperledger-fabric-peer
docker pull yeasy/hyperledger-fabric-orderer
docker tag yeasy/hyperledger-fabric-ca:latest hyperledger/fabric-ca:latest
docker tag yeasy/hyperledger-fabric-peer:latest hyperledger/fabric-peer:latest
docker tag yeasy/hyperledger-fabric-orderer:latest hyperledger/fabric-orderer:latest

# run tests
echo "===Starting test..."
make unittest
