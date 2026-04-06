#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_NAME="${CLUSTER_NAME:-ingress-dev}"
KUBECONFIG_PATH="${KUBECONFIG_PATH:-${ROOT_DIR}/.kube/config}"

if ! command -v kind >/dev/null 2>&1; then
  echo "kind is required (https://kind.sigs.k8s.io/)" >&2
  exit 1
fi

if kind get clusters 2>/dev/null | grep -Fxq "${CLUSTER_NAME}"; then
  kind delete cluster --name "${CLUSTER_NAME}"
  echo "kind cluster removed: ${CLUSTER_NAME}"
else
  echo "kind cluster not found: ${CLUSTER_NAME}"
fi

if [[ -f "${KUBECONFIG_PATH}" ]]; then
  rm -f "${KUBECONFIG_PATH}"
fi
