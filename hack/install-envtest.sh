#!/usr/bin/env bash
set -euo pipefail

K8S_VERSION=1.22.1

# amd64 should be $(go env GOARCH) , but there are no arm64 bins
curl -Lo /tmp/envtest-bins.tar.gz "https://storage.googleapis.com/kubebuilder-tools/kubebuilder-tools-${K8S_VERSION}-$(go env GOOS)-amd64.tar.gz"
mkdir -p testbin
tar -C testbin --strip-components=2 -zvxf /tmp/envtest-bins.tar.gz
