package main

import (
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"

	"github.com/open-policy-agent/opa/rego"
)

var xForwardedFor = http.CanonicalHeaderKey("X-Forwarded-For")

type Authorizer interface {
	// Authorize returns nil if the request should be allowed, or an error if the
	// request should be denied. The error message will be displayed to the user.
	Authorize(r *http.Request) error
}

type AuthorizerFunc func(r *http.Request) error

func (f AuthorizerFunc) Authorize(r *http.Request) error {
	return f(r)
}

var (
	tmplAccessDenied = template.Must(template.New("").Parse(`
<h1>Access Denied</h1>
<hr>
{{ .Error }}
  `))
)

func httpPolicyHandler(next http.Handler, authorizer Authorizer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := authorizer.Authorize(r); err != nil {
			w.WriteHeader(http.StatusForbidden)
			_ = tmplAccessDenied.Execute(w, struct {
				Error string
			}{
				Error: err.Error(),
			})

			return
		}

		next.ServeHTTP(w, r)
	})
}

func regoAuthorize(r *http.Request, q rego.PreparedEvalQuery) error {
	ip, err := clientIP(r)
	if err != nil {
		return err
	}

	results, err := q.Eval(r.Context(), rego.EvalInput(map[string]interface{}{
		"request": map[string]interface{}{
			"method":    r.Method,
			"path":      r.URL.Path,
			"client_ip": ip.String(),
		},
	}))

	if err != nil {
		return err
	} else if len(results) == 0 || len(results[0].Expressions) == 0 {
		return errors.New("query failed to return results")
	} else if result, ok := results[0].Expressions[0].Value.(bool); !ok {
		return errors.New("query returned non-bool result")
	} else if !result {
		return errors.New("denied by rule")
	}

	return nil
}

func clientIP(r *http.Request) (net.IP, error) {
	ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, err
	}

	if xff := r.Header.Get(xForwardedFor); xff != "" {
		sp := strings.Split(xff, ",")
		ipStr = strings.TrimSpace(sp[len(sp)-1])
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP: %v", ip)
	}

	return ip, nil
}
