#!/bin/bash -uex
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -o pipefail -o noglob

if [[ $# != 2 ]]; then
    echo "ERROR: Expecting 2 args"
    echo "usage: $(basename $0) prev next"
    exit 1
fi
echo "## $2" > CHANGELOG.new
echo "$(date -u)" >> CHANGELOG.new
echo "" >> CHANGELOG.new
git log $1..$2 --oneline | grep -v Merge | sed \
   -e 's:\[\(\(FAB\|FABP\)-[0-9]*\)\]*:\[\1\](https\:\/\/jira.hyperledger.org\/brwose\/\1):'      \
   -e 's: \(\(FAB\|FABP\)-[0-9]*\): \[\1\](https\:\/\/jira.hyperledger.org\/browse\/\1):'         \
   -e 's:\([0-9|a-z]*\):* \[\1\](https\:\/\/github.com\/hyperledger\/fabric-sdk-py\/commit\/\1):' \
    >> CHANGELOG.new
echo "" >> CHANGELOG.new

# Prepend the new log entries to the top of the old log
cat CHANGELOG.md >> CHANGELOG.new
mv -f CHANGELOG.new CHANGELOG.md
