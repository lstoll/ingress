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

The local deployment currently runs `ingress` with `--cert-mode=self-signed` as groundwork for terminated TLS routes.

## Deploy

```bash
skaffold run
```

Skaffold builds the local `ingress` image and applies `deploy/dev` manifests (Gateway, TLSRoute, ingress workload, and demo TLS backend).

By default, the ingress process watches routes cluster-wide and filters to the configured Gateway via `parentRefs`.
The demo `TLSRoute` disables proxy-protocol so a plain nginx TLS backend can terminate the connection directly.

To test ingress-side TLS termination (TLS at ingress, HTTP backend), use:

```bash
skaffold run -p terminate
```

This uses `deploy/dev-terminate`, switches the Gateway listener to `Terminate`, and points the backend to plain HTTP on port `8080`.

## Production-style autocert mode

For real certificate issuance, run ingress with `--cert-mode=autocert` and provide a cache secret:

```bash
/ingress \
  --gateway-name=ingress \
  --gateway-namespace=ingress-dev \
  --listener-name=tls \
  --cert-mode=autocert \
  --autocert-secret=ingress-dev/autocert-cache
```

Notes:

- `--autocert-secret` is required in `namespace/name` format.
- ACME/TLS-ALPN validation requires external reachability on port `443` for the requested hostnames.

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

When using `-p terminate`, expected response body becomes:

```text
hello from demo backend (http)
```

## Tear down

```bash
./hack/kind-down.sh
```
