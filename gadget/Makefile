CONTAINER_REPO ?= ghcr.io/blanquicet/tcprst-gadget
CONTAINER_REPO_WITHOUT_NF ?= ghcr.io/blanquicet/tcprst-gadget-without-nf
IMAGE_TAG ?= latest

# NOTE: ig version must include the following PR
# https://github.com/inspektor-gadget/inspektor-gadget/pull/2331
# This is because the tcprst gadget uses gadget_output_buf() which is not
# available in the latest release: v0.24.0.

.PHONE: build-all
build-all: build-without-nf build

# The build-without-nf target uses the build-without-nf.yaml to set the correct
# environment variables that build the image without the kprobes that require
# the nf_reject_ipv4 module to be loaded.
.PHONY: build-without-nf
build-without-nf:
	IG_EXPERIMENTAL=true sudo -E \
		ig image build \
			-t $(CONTAINER_REPO_WITHOUT_NF):$(IMAGE_TAG) \
			-f build-without-nf.yaml \
			--update-metadata .

# Instead, the build target uses the default values for building the image so
# that it includes all the features.
.PHONY: build
build:
	IG_EXPERIMENTAL=true sudo -E \
		ig image build \
			-t $(CONTAINER_REPO):$(IMAGE_TAG) \
			--update-metadata .

.PHONY: run-all
run-all: run-without-nf run

# PARAMS can be used to pass additional parameters locally e.g
# PARAMS="-o jsonpretty" make run
.PHONY: run-without-nf
run-without-nf:
	IG_EXPERIMENTAL=true sudo -E \
		ig run $(CONTAINER_REPO_WITHOUT_NF):$(IMAGE_TAG) $$PARAMS

# PARAMS can be used to pass additional parameters locally e.g
# PARAMS="-o jsonpretty" make run
.PHONY: run
run:
	IG_EXPERIMENTAL=true sudo -E \
		ig run $(CONTAINER_REPO):$(IMAGE_TAG) $$PARAMS

.PHONY: push-all
push-all: push-without-nf push

.PHONY: push-without-nf
push-without-nf:
	IG_EXPERIMENTAL=true sudo -E \
		ig image push $(CONTAINER_REPO_WITHOUT_NF):$(IMAGE_TAG)

.PHONY: push
push:
	IG_EXPERIMENTAL=true sudo -E \
		ig image push $(CONTAINER_REPO):$(IMAGE_TAG)