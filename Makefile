# SPDX-License-Identifier: Apache-2.0

# Triggered by the ci
# To run some specific case, run like `tox -e py3 -- test/integration/create_channel_test.py`
PATH := fabric-bin/bin:$(PATH)
SHELL := env PATH=$(PATH) /bin/bash
PIP := pip3
PYTHON := python3
check: clean
	scripts/check-env.sh
	echo "=== Testing started... ==="
	make test

# Tox related variables
TOX = tox
TOX_VENV_NAMES = flake8 py36
# [tox.pylint, tox.flake8, tox.py36]
TOX_VENVS = $(patsubst %, $(TOX).%, $(TOX_VENV_NAMES))

# Run all unit test cases
test: venv
	source venv/bin/activate ; make $(TOX_VENVS)

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

PREV_VERSION?=1.0.0

# changelog update
changelog:
	scripts/changelog.sh df19cf5 HEAD v$(PREV_VERSION)

# Generate the hyperledger/fabric-sdk-py image
image:
	docker build -t hyperledger/fabric-sdk-py .

# Generate the protobuf python files
proto:
	shopt -s globstar
	$(PYTHON) -m grpc.tools.protoc \
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
	@echo "virtualenv can be installed by: pip3 install virtualenv"
	rm -rf venv
	virtualenv -p $(PYTHON) venv
	source venv/bin/activate;\
		$(PIP) install tox;\
		$(PYTHON) --version;\
		$(PIP) --version;\
		tox --version;\
		$(PIP) install -r requirements.txt;\
		$(PIP)  install -r requirements-test.txt
	@echo "Active the virtual env: source venv/bin/activate"
	@echo "Deactive when done: deactivate"

# Install sdk to local python env
install:
	$(PYTHON) setup.py install

# Auto-format to pep8
format:
	$(PYTHON) -m autopep8 --in-place --recursive --exclude=protos,venv .

doc:
	cd docs && make install html

.PHONY: check \
		clean \
		doc \
		proto \
		image \
		install \
		format \
		test \
		venv
