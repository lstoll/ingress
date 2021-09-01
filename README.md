# ingress

ingress.

it's a sidecar, that can be the target of an internet facing kubernetes service (i.e elb or nlb)

it handles:
* TLS via LetsEncrypt
* Auth via OIDC web flow
* Auth via OIDC token in header
* IP Allowlist Enforcement
* Managed device client cert auth.
* Passing user info back

Basically, everything needed to safely expose a service to the internet. It's mostly a simple close to the app hack to get stuff out there fast
