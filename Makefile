define run-py-tox
	@echo "run python tox $@"
	# set -o pipefail
	rm -rf .tox/$@/log
	# bin_path=.tox/$@/bin
	# export PYTHON=$bin_path/python
	tox -v -e$@
	# set +o pipefail
endef

# Triggered by the ci
check:
	bash check.sh

# Run all unit test cases
unittest: pylint flake8 py27 py35

pylint:
	$(call run-py-tox)

py27:
	$(call run-py-tox)

py30:
	$(call run-py-tox)

py35:
	$(call run-py-tox)

flake8:
	$(call run-py-tox)

# Generate the hyperledger/fabric-sdk-py image
.PHONY: image
image:
	docker build -t hyperledger/fabric-sdk-py .

# Generate the protobuf python files
.PHONY: proto
proto:
	python3 -m grpc.tools.protoc \
		-I./hfc/protos/\
		--python_out=./hfc/protos \
		--grpc_python_out=./hfc/protos \
		hfc/protos/common/*.proto \
		hfc/protos/msp/*.proto \
		hfc/protos/orderer/*.proto \
		hfc/protos/peer/chaincode.proto \
		hfc/protos/peer/chaincode_proposal.proto \
		hfc/protos/peer/chaincode_transaction.proto \
		hfc/protos/peer/chaincodeevent.proto \
		hfc/protos/peer/events.proto \
		hfc/protos/peer/fabric.proto \
		hfc/protos/peer/fabric_block.proto \
		hfc/protos/peer/fabric_message.proto \
		hfc/protos/peer/fabric_proposal.proto \
		hfc/protos/peer/fabric_proposal_response.proto \
		hfc/protos/peer/fabric_service.proto \
		hfc/protos/peer/fabric_transaction.proto
