# Tox running function
define run-py-tox
	@echo "run python tox $(1)"
	# set -o pipefail
	rm -rf .tox/$(1)/log
	# bin_path=.tox/$(1)/bin
	# export PYTHON=$bin_path/python
	tox -v -e$(1) test
	# set +o pipefail
endef

# Tox related variables
TOX = tox
TOX_VENV_NAMES = pylint flake8 py27 py30 py35
TOX_VENVS = $(patsubst %, $(TOX).%, $(TOX_VENV_NAMES))

# Triggered by the ci
check:
	bash check.sh

# Run all unit test cases
.PHONY: unittest

unittest: $(TOX_VENVS)

$(TOX).%:
	$(eval TOX_VENV_NAME = ${subst $(TOX).,,${@}})
	$(call run-py-tox,$(TOX_VENV_NAME))

# Generate the hyperledger/fabric-sdk-py image
.PHONY: image
image:
	docker build -t hyperledger/fabric-sdk-py .

# Generate the protobuf python files
.PHONY: proto
proto:
	python3 -m grpc.tools.protoc \
		-I./\
		--python_out=./ \
		--grpc_python_out=./ \
		hfc/protos/**/*.proto

# Clean temporary files
.PHONY: clean
clean:
	rm -rf .cache *.egg-info .tox .coverage .coverage.*
	find . -name "*.pyc" -exec rm -rf "{}" \;
