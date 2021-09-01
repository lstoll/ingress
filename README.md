# ingress

ingress.

it's a sidecar, that can be the target of an internet facing kubernetes service (i.e elb or nlb)

it handles:
* TLS via LetsEncrypt :white_check_mark:
* Auth via OIDC web flow :white_check_mark:
* Auth via OIDC token in header :x:
* IP Allowlist Enforcement :white_check_mark:
* Managed device client cert auth. :x:
* Passing user info back :x:

Basically, everything needed to safely expose a service to the internet. It's mostly a simple close to the app hack to get stuff out there fast
