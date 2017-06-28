#!/bin/bash
set -x
# checking local version
echo "===Checking Docker and Docker-Compose version"
docker version
docker-compose -v

# install tox
pip install tox

# pull fabric images
ARCH=x86_64
BASEIMAGE_RELEASE=0.3.1
BASE_VERSION=1.0.0
PROJECT_VERSION=1.0.0-rc1
IMG_TAG=v1.0.0-rc1

echo "===Pulling fabric images... with tag = ${IMG_TAG}"
docker pull yeasy/hyperledger-fabric-base:$IMG_TAG
docker pull yeasy/hyperledger-fabric-peer:$IMG_TAG
docker pull yeasy/hyperledger-fabric-orderer:$IMG_TAG
docker pull yeasy/hyperledger-fabric-ca:$IMG_TAG

docker tag yeasy/hyperledger-fabric-peer:$IMG_TAG hyperledger/fabric-peer
docker tag yeasy/hyperledger-fabric-peer:$IMG_TAG hyperledger/fabric-tools
docker tag yeasy/hyperledger-fabric-orderer:$IMG_TAG hyperledger/fabric-orderer
docker tag yeasy/hyperledger-fabric-ca:$IMG_TAG hyperledger/fabric-ca
docker tag yeasy/hyperledger-fabric-base:$IMG_TAG hyperledger/fabric-ccenv:$ARCH-$PROJECT_VERSION
docker tag yeasy/hyperledger-fabric-base:$IMG_TAG hyperledger/fabric-baseos:$ARCH-$BASEIMAGE_RELEASE
docker tag yeasy/hyperledger-fabric-base:$IMG_TAG hyperledger/fabric-baseimage:$ARCH-$BASEIMAGE_RELEASE

# run tests
echo "===Starting test..."
make unittest