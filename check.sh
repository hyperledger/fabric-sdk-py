#!/bin/bash
set -x
# checking local version
echo "===Checking Docker and Docker-Compose version"
docker version
docker-compose -v

# pull fabric images
IMG_TAG=0.8.5
echo "===Pulling fabric images... with tag = ${IMG_TAG}"
docker pull yeasy/hyperledger-fabric-base:$IMG_TAG
docker pull yeasy/hyperledger-fabric-peer:$IMG_TAG
docker pull yeasy/hyperledger-fabric-orderer:$IMG_TAG
docker pull yeasy/hyperledger-fabric-ca:$IMG_TAG

docker tag yeasy/hyperledger-fabric-base:$IMG_TAG hyperledger/fabric-baseimage
docker tag yeasy/hyperledger-fabric-base:$IMG_TAG hyperledger/fabric-ccenv:x86_64-1.0.0-preview
docker tag yeasy/hyperledger-fabric-peer:$IMG_TAG hyperledger/fabric-peer
docker tag yeasy/hyperledger-fabric-orderer:$IMG_TAG hyperledger/fabric-orderer
docker tag yeasy/hyperledger-fabric-ca:$IMG_TAG hyperledger/fabric-ca

# run tests
echo "===Starting test..."
make unittest