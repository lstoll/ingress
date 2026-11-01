# Design

The goal is a simple, flexible ingress setup for homelab-level k8s.

While standard APIs exist in Kubernetes for this (i.e Gateway API), they are a bit verbose and inflexible for our desired use. So here, we go for a simpler setup that is just based on annotations on the service that is needed anyway.

The types of ingress-able traffic are:

* On a single TCP listener, routed via SNI header (multiple backend services):
  * TLS passthrough
  * TLS termination with an automatically provisioned cert
    * Optional mTLS to the backend
  * HTTPS, terminated with a automatically provisioned cert
    * This can optionally enforce OIDC auth, passing user info through
    * CEL policies, to determine if auth is needed and to map claims to headers
    * Optional mTLS to the backend
* On a single TCP listener, a HTTP redirect. This listens for plain HTTP, and if there is a TLS/HTTPS backend configured for the incoming hostname a redirect to HTTPS happens.
* On a single TCP listener, raw TCP to a backend. The TCP listener is named, and the service is annotated with the expected name. Only one service can exist for a gived named raw TCP listener, as we get no routable info. For SMTP etc.
  * Optional mTLS wrapping (requires remote termination to unwrap the underlying connection) to verify connections from the LB.

The cmd/ingress runs at the edge, with incoming traffic via a LB/NodePort service. Each process is named with an "instance" value, which determines what services it should watch for.

cmd/sidecar is a future enhancement, designed to do the mTLS unwrapping + verification. Maybe other future "next to pod" ideas.

## Example Services

### TLS passthrough to backend

```
apiVersion: v1
kind: Service
metadata:
  name: tls-passthrough-service
  labels:
    ingress.lds.li/instance: "ingress1"
  annotations:
    ingress.lds.li/mode: "tls-passthrough"
    ingress.lds.li/sni-hostnames: "host1.example.com,host2.example.com"
    ingress.lds.li/proxy-protocol: "v1"
spec:
  selector:
    app.kubernetes.io/name: tls-serving-app
  ports:
    - protocol: TCP
      port: 443
      targetPort: 8443
```

### TLS termination

```
apiVersion: v1
kind: Service
metadata:
  name: tls-termination-service
  labels:
    ingress.lds.li/instance: "ingress1"
  annotations:
    ingress.lds.li/mode: "tls-termination"
    ingress.lds.li/sni-hostnames: "host3.example.com"
spec:
  selector:
    app.kubernetes.io/name: plain-serving-app
  ports:
    - protocol: TCP
      port: 443
      targetPort: 8443
```

### HTTPS, no auth

```
apiVersion: v1
kind: Service
metadata:
  name: tls-termination-service
  labels:
    ingress.lds.li/instance: "ingress1"
  annotations:
    ingress.lds.li/mode: "https"
    ingress.lds.li/hostnames: "website.example.com"
spec:
  selector:
    app.kubernetes.io/name: open-webapp
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8080
```

### HTTPS, OIDC auth

```
apiVersion: v1
kind: Service
metadata:
  name: tls-termination-service
  labels:
    ingress.lds.li/instance: "ingress1"
  annotations:
    ingress.lds.li/mode: "https"
    ingress.lds.li/hostnames: "authed.example.com"
    ingress.lds.li/auth-mode: "OIDC"
    ingress.lds.li/oidc-issuer: "https://id.lds.li"
    ingress.lds.li/oidc-dynamic-client: true
    ingress.lds.li/oidc-preferred-username-header: "Remote-User"
    ingress.lds.li/oidc-email-header: "Remote-User-Email"
    ingress.lds.li/require-group: "admin"
spec:
  selector:
    app.kubernetes.io/name: secure-webapp
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8080
```

### HTTPS, OIDC auth with private_key_jwt

Instead of a static client secret, ingress can authenticate to the IdP's token
endpoint with signed client assertions (RFC 7523 `private_key_jwt`). Start
ingress with `--oidc-client-keyset-secret=<namespace>/<name>`. Ingress keeps one
ES256 keyset in that Secret, shared by every host, and rotates it daily. A new
key is published 6h before it starts signing, and old keys stay published for
6h after.

Each host using this mode serves the public keys at
`https://<host>/.ingress/oidc-jwks`. Ingress answers this path itself, ahead of
auth and bypass patterns. Register the client at the IdP with that URL as its
JWKS URL (passidp: `jwksURL`) and no secret.

```
    ingress.lds.li/auth-mode: "OIDC"
    ingress.lds.li/oidc-issuer: "https://id.lds.li"
    ingress.lds.li/oidc-client-id: "authed-app"
    ingress.lds.li/oidc-client-auth: "private_key_jwt"
```

`private_key_jwt` requires an explicit client id, and cannot be combined with a
client secret or dynamic registration. Services that ask for it are ignored if
ingress was started without a keyset.

The Secret is stored in cleartext. Pre-create it empty and grant ingress
`get`/`update` on that name only (see `deploy/dev/ingress-rbac.yaml`); otherwise
ingress needs `create` on secrets in that namespace.

### TCP

```
apiVersion: v1
kind: Service
metadata:
  name: tls-termination-service
  labels:
    ingress.lds.li/instance: "ingress1"
  annotations:
    ingress.lds.li/mode: "tcp"
    ingress.lds.li/tcp-listener: "smtp"
spec:
  selector:
    app.kubernetes.io/name: mailserver
  ports:
    - protocol: TCP
      port: 25
      targetPort: 2525
```
