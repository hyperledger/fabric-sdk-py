# SPDX-License-Identifier: Apache-2.0

# Triggered by the ci
# To run some specific case, run like `tox -e py30 -- test/integration/create_channel_test.py`
PATH := fabric-bin/bin:$(PATH)
SHELL := env PATH=$(PATH) /bin/bash
check: clean
	bash ./scripts/check_env.sh
	echo "=== Testing started... ==="
	make test

# Tox related variables
TOX = tox
TOX_VENV_NAMES = pylint flake8 py30 py35
# [tox.pylint, tox.flake8, tox.py30, tox.py35]
TOX_VENVS = $(patsubst %, $(TOX).%, $(TOX_VENV_NAMES))

# Run all unit test cases
test: $(TOX_VENVS)

$(TOX).%:
	$(eval TOX_VENV_NAME = ${subst $(TOX).,,${@}})
	$(call run-py-tox,$(TOX_VENV_NAME))

# Tox running function
define run-py-tox
	@echo ">>> Tox test: $(1) ..."
	# set -o pipefail
	@rm -rf .tox/$(1)/log
	# bin_path=.tox/$(1)/bin
	# export PYTHON=$bin_path/python
	@tox -v -e$(1) test
	# set +o pipefail
endef

# Check the format
flake8: linter

linter:
	tox -e flake8

PREV_VERSION?=0.7.0

# changelog update
changelog:
	# bash scripts/changelog.sh 838e035 v$(PREV_VERSION)
	bash scripts/changelog.sh v$(PREV_VERSION) HEAD

# Generate the hyperledger/fabric-sdk-py image
image:
	docker build -t hyperledger/fabric-sdk-py .

# Generate the protobuf python files
proto:
	python3 -m grpc.tools.protoc \
		-I./\
		--python_out=./ \
		--grpc_python_out=./ \
		hfc/protos/**/*.proto

# Clean temporary files
clean:
	rm -rf .cache *.egg-info .tox .coverage .coverage.* test/fixtures/ca/fabric-ca-server/fabric-ca-server.db test/fixtures/ca/fabric-ca-server/keystore/0e729224e8b3f31784c8a93c5b8ef6f4c1c91d9e6e577c45c33163609fe40011_sk
	find . -name "*.pyc" -o -name "__pycache__" | xargs rm -rf
	rm -rf ./venv

# Enter a virtual env
venv:
	if [ ! -d venv ]; then \
		virtualenv venv; \
	fi
	@echo "Run 'source venv/bin/activate' to active the virtual env now."

install: # Install sdk to local python env
	python3 setup.py install

.PHONY: check clean proto image install test venv
