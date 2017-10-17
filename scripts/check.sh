# SPDX-License-Identifier: Apache-2.0
#

#!/bin/bash -eu


# checking local version
echo "===> Checking Docker and Docker-Compose version"
docker version
echo
docker-compose -v

# install tox
pip install tox

# pull fabric images
ARCH=x86_64
BASEIMAGE_RELEASE=0.3.1
BASE_VERSION=1.0.0
PROJECT_VERSION=1.0.0
IMG_TAG=1.0.0


dockerFabricPull() {
  local FABRIC_TAG=$1
  for IMAGES in peer tools orderer ccenv ca; do
      echo "==> FABRIC IMAGE: $IMAGES"
      echo
      docker pull hyperledger/fabric-$IMAGES:$FABRIC_TAG
      docker tag hyperledger/fabric-$IMAGES:$FABRIC_TAG hyperledger/fabric-$IMAGES
  done
}

: ${FABRIC_TAG:="$ARCH-$IMG_TAG"}

echo "=====> Pulling fabric Images"
dockerFabricPull ${FABRIC_TAG}

docker pull hyperledger/fabric-baseimage:$ARCH-$BASEIMAGE_RELEASE
docker pull hyperledger/fabric-baseos:$ARCH-$BASEIMAGE_RELEASE

# run tests
echo "===Starting test..."
make unittest
