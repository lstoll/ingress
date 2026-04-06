#!/usr/bin/env bash
set -euo pipefail

mkdir -p testbin/crds
curl -sLo testbin/crds/gateway-api.yaml https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.1/experimental-install.yaml

go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
ASSETS=$(setup-envtest use -p path --bin-dir testbin 1.30.x)
mkdir -p testbin/bin
cp -a $ASSETS/* testbin/bin/
