#!/usr/bin/env bash

# Define those global variables
if [ -f ./variables.sh ]; then
 source ./variables.sh
elif [ -f ./scripts/variables.sh ]; then
 source ./scripts/variables.sh
else
    echo "Cannot find the variables.sh files, pls check"
    exit 1
fi

if [ -d e2e_cli/${CHANNEL_ARTIFACTS} ];
then
    echo "removing channel-artifacts..."
    rm -r e2e_cli/${CHANNEL_ARTIFACTS}
else
    echo "channel-artifacts not exists..."
fi

if [ -d e2e_cli/crypto-config ];
then
    echo "removing crypto-config..."
    rm -r e2e_cli/crypto-config
else
    echo "crypto-config not exists..."
fi
