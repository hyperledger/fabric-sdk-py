# SPDX-License-Identifier: Apache-2.0

# Triggered by the ci
# To run some specific case, run like `tox -e py30 -- test/integration/create_channel_test.py`
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


# changelog update
# TODO (dpdornseifer): As long as there is no versioning, always write the changelog
# starting with the initial commit INIT_VERSION (bug)
changelog:
	INIT_VERSION = 838e035
	bash ./scripts/changelog.sh $(INIT_VERSION)

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
	rm -rf .cache *.egg-info .tox .coverage .coverage.* test/fixtures/ca/fabric-ca-server/fabric-ca-server.db
	find . -name "*.pyc" -o -name "__pycache__" | xargs rm -rf

.PHONY: check clean proto image test
