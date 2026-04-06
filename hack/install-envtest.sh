#!/usr/bin/env bash
set -euo pipefail

go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
ASSETS=$(setup-envtest use -p path --bin-dir testbin 1.30.x)
mkdir -p testbin/bin
cp -a $ASSETS/* testbin/bin/
