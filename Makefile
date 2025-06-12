GO ?= $(shell which go)
OS ?= $(shell $(GO) env GOOS)
ARCH ?= $(shell $(GO) env GOARCH)

IMAGE_NAME := "rabbitlhf/cert-manager-webhook-volcengine"
IMAGE_TAG := "latest"

OUT := $(shell pwd)/_out

KUBEBUILDER_VERSION=1.28.0

$(shell mkdir -p "$(OUT)")
export TEST_ASSET_ETCD=_test/kubebuilder/bin/etcd
export TEST_ASSET_KUBE_APISERVER=_test/kubebuilder/bin/kube-apiserver
export TEST_ASSET_KUBECTL=_test/kubebuilder/bin/kubectl

test: _test/kubebuilder
	go test -v .

_test/kubebuilder:
	curl -fsSL https://go.kubebuilder.io/test-tools/$(KUBE_VERSION)/$(OS)/$(ARCH) -o kubebuilder-tools.tar.gz
	mkdir -p _test/kubebuilder
	tar -xvf kubebuilder-tools.tar.gz
	mv kubebuilder/bin _test/kubebuilder/
	rm kubebuilder-tools.tar.gz
	rm -R kubebuilder

clean: clean-kubebuilder

clean-kubebuilder:
	rm -Rf _test/kubebuilder

build:
	docker build -t "$(IMAGE_NAME):$(IMAGE_TAG)" .

.PHONY: rendered-manifest.yaml
rendered-manifest.yaml:
	helm template \
	        --name cert-manager-webhook-volcengine \
            --set image.repository=$(IMAGE_NAME) \
            --set image.tag=$(IMAGE_TAG) \
            deploy/cert-manager-webhook-volcengine > "$(OUT)/rendered-manifest.yaml"
