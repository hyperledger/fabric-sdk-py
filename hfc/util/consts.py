# SPDX-License-Identifier: Apache-2.0

SYSTEM_CHANNEL_NAME = "testchainid"

CC_INSTALL = "install"
CC_INSTANTIATE = "deploy"
CC_INVOKE = "invoke"
CC_UPGRADE = "upgrade"
CC_QUERY = "query"

# lifecycle
LIFECYCLE_CC = "_lifecycle"
LC_INSTALL = "InstallChaincode"
LC_APPROVE_FOR_MY_ORG = "ApproveChaincodeDefinitionForMyOrg"
LC_COMMIT = "CommitChaincodeDefinition"
LC_QUERY_INSTALLED = "QueryInstalledChaincodes"
LC_QUERY_APPROVED = "QueryApprovedChaincodeDefinition"
LC_QUERY_CC_DEFINITION = "QueryChaincodeDefinition"
LC_QUERY_CC_DEFINITIONS = "QueryChaincodeDefinitions"

CC_TYPE_GOLANG = "GOLANG"
CC_TYPE_JAVA = "JAVA"
CC_TYPE_NODE = "NODE"
CC_TYPE_CAR = "CAR"

DEFAULT_WAIT_FOR_EVENT_TIMEOUT = 30  # s
GRPC_BROKER_UNAVAILABLE_RETRY_DELAY = 3000  # ms

SUCCESS_STATUS = 200
