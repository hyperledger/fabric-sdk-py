define run-py-tox
	@echo "run python tox $@"
	# set -o pipefail
	rm -rf .tox/$@/log
	# bin_path=.tox/$@/bin
	# export PYTHON=$bin_path/python
	tox -v -e$@
	# set +o pipefail
endef

# Run all test cases, and should be triggered by the ci
check: pylint py27 py30 py35 flake8

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
.PHONY: docker
docker:
	docker build -t hyperledger/fabric-sdk-py .

# Generate the protobuf python files
.PHONY: proto
proto:
	python -m grpc.tools.protoc \
		-I./hfs/protos \
		--python_out=./hfs/protos \
		--grpc_python_out=./hfs/protos \
		hfs/protos/*.proto
