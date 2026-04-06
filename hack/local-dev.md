# Local Gateway API dev loop

This repo now has a local kind + skaffold setup for the `ingress` gateway process.

## Prerequisites

- `kind`
- `kubectl`
- `skaffold`
- `direnv` (optional but recommended)

## One-time setup

```bash
direnv allow
```

The checked-in `.envrc` points `KUBECONFIG` at `.kube/config` in this repo.

## Start cluster

```bash
./hack/kind-up.sh
```

This script:

- creates a kind cluster named `ingress-dev` with host port `8443` mapped to NodePort `30443`
- writes kubeconfig to `.kube/config`
- installs Gateway API standard CRDs (server-side apply)

## Deploy

```bash
skaffold run
```

Skaffold builds the local `ingress` image and applies `deploy/dev` manifests (Gateway, TLSRoute, ingress workload, and demo TLS backend).

By default, the ingress process watches routes cluster-wide and filters to the configured Gateway via `parentRefs`.
The demo `TLSRoute` disables proxy-protocol so a plain nginx TLS backend can terminate the connection directly.

## Verify

```bash
kubectl -n ingress-dev get gateway,service,tlsroute,pods
```

```bash
kubectl -n ingress-dev logs deploy/ingress --tail=100
```

Use curl with SNI/hostname:

```bash
curl -vk --resolve app.localtest.me:8443:127.0.0.1 https://app.localtest.me:8443/
```

Expected response body:

```text
hello from demo backend (tls)
```

## Tear down

```bash
./hack/kind-down.sh
```
