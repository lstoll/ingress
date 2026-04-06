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
- installs baseline cluster prerequisites for this repo

The local deployment currently runs `ingress` with `--cert-mode=self-signed` as groundwork for terminated TLS routes.

## Deploy

```bash
skaffold run
```

Skaffold builds the local `ingress` image and applies `deploy/dev` manifests (one ingress deployment and two annotated backend services).

Ingress runs on a single listener and routes by SNI hostname from service annotations:

- `pass.localtest.me` -> TLS passthrough backend
- `term.localtest.me` -> TLS terminated at ingress, then plain HTTP to backend

## Production-style autocert mode

For real certificate issuance, run ingress with `--cert-mode=autocert` and provide a cache secret:

```bash
/ingress \
  --instance=ingress1 \
  --cert-mode=autocert \
  --autocert-secret=ingress-dev/autocert-cache
```

Notes:

- `--autocert-secret` is required in `namespace/name` format.
- ACME/TLS-ALPN validation requires external reachability on port `443` for the requested hostnames.

## Verify

```bash
kubectl -n ingress-dev get service,pods
```

```bash
kubectl -n ingress-dev logs deploy/ingress --tail=100
```

Passthrough curl:

```bash
curl -vk --resolve pass.localtest.me:8443:127.0.0.1 https://pass.localtest.me:8443/
```

Expected response body:

```text
hello from demo backend (tls)
```

Terminate curl:

```bash
curl -vk --resolve term.localtest.me:8443:127.0.0.1 https://term.localtest.me:8443/
```

Expected response body:

```text
hello from demo backend (http)
```

## Tear down

```bash
./hack/kind-down.sh
```
