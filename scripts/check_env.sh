# SPDX-License-Identifier: Apache-2.0
#

#!/bin/bash -eu

dockerFabricPull() {
  local IMG_TAG=$1
  for IMAGES in peer tools orderer ccenv ca; do
      HLF_IMG=hyperledger/fabric-$IMAGES:${IMG_TAG}
      echo "==> Check IMAGE: ${HLF_IMG}"
			if [ -z "$(docker images -q ${HLF_IMG} 2> /dev/null)" ]; then  # not exist
				docker pull ${HLF_IMG}
			else
				echo "${HLF_IMG} already exist locally"
			fi
  done
}

# checking local version
echo "===> Checking Docker and Docker-Compose version"
docker version
echo
docker-compose -v

which tox

if [ $? -eq 0 ] ; then
   echo "====> tox is already installed"
   echo
else
   echo "====> install tox here"
   echo
   pip install tox
fi

# pull fabric images
ARCH=x86_64
BASEIMAGE_RELEASE=0.3.1
BASE_VERSION=1.0.0
PROJECT_VERSION=1.0.0
IMG_TAG=1.0.0

: ${FABRIC_TAG:="$ARCH-$IMG_TAG"}

echo "=====> Pulling fabric Images"
dockerFabricPull ${FABRIC_TAG}

IMG=hyperledger/fabric-baseimage:$ARCH-$BASEIMAGE_RELEASE
[ -z "$(docker images -q ${IMG} 2> /dev/null)" ] && docker pull ${IMG}

IMG=hyperledger/fabric-baseos:$ARCH-$BASEIMAGE_RELEASE
[ -z "$(docker images -q ${IMG} 2> /dev/null)" ] && docker pull ${IMG}

if ! which configtxgen
	then
		if  [ ! -e fabric-bin/bin/configtxgen ];
		then
			echo "configtxgen doesn't exits."
			mkdir -p fabric-bin
			PLATFORM=$(echo "$(uname -s|tr '[:upper:]' '[:lower:]'|
            sed 's/mingw64_nt.*/windows/')-$(uname -m | sed 's/x86_64/amd64/g')" | awk '{print tolower($0)}')
			echo "===> Downloading platform specific fabric binaries"
			binUrl="https://nexus.hyperledger.org/content/repositories/releases/org" \
            binUrl="$binUrl/hyperledger/fabric/hyperledger-fabric/${PLATFORM}-${PROJECT_VERSION}" \
            binUrl="$binUrl/hyperledger-fabric-${PLATFORM}-${PROJECT_VERSION}.tar.gz"
            cd fabric-bin && curl $binUrl | tar xz;
			if [ $? -gt 0 ];
			then
				echo "Binary download failed."
				exit 1
			fi
		fi
	fi

exit 0