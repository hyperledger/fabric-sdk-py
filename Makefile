# Run all test cases, and should be triggered by the ci
.PHONY: check
check:
	tox

# Generate the hyperledger/fabric-sdk-py image
.PHONY: docker
docker:
	build -t hyperledger/fabric-sdk-py .
