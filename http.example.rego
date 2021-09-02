package http

tailscale_cidrs := [
	"100.64.0.0/10",
	"fd7a:115c:a1e0::/48"
]

default allow = false

# Loopback
allow {
	input.request.client_ip == "127.0.0.1"
}

# Any presented client certificate
allow {
	input.request.client_cn != ""
}

allow {
	count(net.cidr_contains_matches(tailscale_cidrs, input.request.client_ip)) > 0
}

# Health endpoint
allow {
	input.request.method == "GET"
	input.request.path == "/healthz"
}
