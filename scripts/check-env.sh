#! /bin/bash -ue
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -o pipefail -o noglob

dockerFabricPull() {
  local img_tag=$1
  for images in peer tools orderer ccenv ca; do
      local hlf_img=hyperledger/fabric-$images:$img_tag
      echo "==> Check IMAGE: $hlf_img"
      if [[ -z "$(docker images -q $hlf_img 2> /dev/null)" ]]; then  # not exist
          docker pull $hlf_img
      else
          echo "Image: $hlf_img already exists locally"
      fi
  done
}

# checking local version
echo "===> Checking Docker and Docker-Compose version"
docker version
echo
docker-compose -v

if type tox; then
   tox_version=$(tox --version)
   echo "====> tox is already installed $tox_version"
   echo
else
   echo "====> install tox here"
   echo
   pip install tox
fi

# pull fabric images
baseimage_release=0.4.14
export BASE_VERSION=1.4.1
project_version=1.4.0
img_tag=1.4.0

: ${fabric_tag:=$img_tag}

echo "=====> Pulling fabric Images"
dockerFabricPull $fabric_tag

img=hyperledger/fabric-baseimage:$baseimage_release
[ -z "$(docker images -q $img 2> /dev/null)" ] && docker pull $img

img=hyperledger/fabric-baseos:$baseimage_release
[ -z "$(docker images -q $img 2> /dev/null)" ] && docker pull $img

if ! type configtxgen; then
    if  [[ ! -e fabric-bin/bin/configtxgen ]]; then
        echo "configtxgen doesn't exits."
        mkdir -p fabric-bin
        kernel=$(uname -s | tr '[:upper:]' '[:lower:]' | sed 's/mingw64_nt.*/windows/')
        machine=$(uname -m | sed 's/x86_64/amd64/g' | tr '[:upper:]' '[:lower:]')
        platform=$kernel-$machine
        echo "===> Downloading '$platform' specific fabric binaries"
        bin_url="https://nexus.hyperledger.org/content/repositories/releases/org"
        bin_url+="/hyperledger/fabric/hyperledger-fabric/$platform-$project_version"
        bin_url+="/hyperledger-fabric-$platform-$project_version.tar.gz"
        if ! curl $bin_url | tar -C fabric-bin -vxz; then
            echo "Binary download failed."
            exit 1
        fi
    fi
fi
