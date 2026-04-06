#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_NAME="${CLUSTER_NAME:-ingress-dev}"
KUBECONFIG_PATH="${KUBECONFIG_PATH:-${ROOT_DIR}/.kube/config}"
KIND_CONFIG_PATH="${ROOT_DIR}/hack/kind-config.yaml"
GATEWAY_API_VERSION="${GATEWAY_API_VERSION:-v1.5.1}"

if ! command -v kind >/dev/null 2>&1; then
  echo "kind is required (https://kind.sigs.k8s.io/)" >&2
  exit 1
fi
if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl is required" >&2
  exit 1
fi

mkdir -p "$(dirname "${KUBECONFIG_PATH}")"

if ! kind get clusters 2>/dev/null | grep -Fxq "${CLUSTER_NAME}"; then
  kind create cluster --name "${CLUSTER_NAME}" --config "${KIND_CONFIG_PATH}"
fi

kind get kubeconfig --name "${CLUSTER_NAME}" > "${KUBECONFIG_PATH}"
export KUBECONFIG="${KUBECONFIG_PATH}"

kubectl apply --server-side --force-conflicts -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/standard-install.yaml"

echo "kind cluster ready: ${CLUSTER_NAME}"
echo "kubeconfig: ${KUBECONFIG_PATH}"
