#!/bin/sh
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

# TODO (dpdornseifer): Switch back to append changelog as soon as version
# tags are introduced. Right now the entire changelog is rewritten every time.
echo "## $(date)" > CHANGELOG.md
echo "" >> CHANGELOG.md
git log $1..HEAD  --oneline | grep -v Merge | sed -e "s/\[\(FAB-[0-9]*\)\]/\[\1\](https:\/\/jira.hyperledger.org\/browse\/\1\)/" -e "s/ \(FAB-[0-9]*\)/ \[\1\](https:\/\/jira.hyperledger.org\/browse\/\1\)/" -e "s/\([0-9|a-z]*\)/* \[\1\](https:\/\/github.com\/hyperledger\/fabric\/commit\/\1)/" >> CHANGELOG.md
echo "" >> CHANGELOG.md
