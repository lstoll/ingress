package main

import (
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestClientIP(t *testing.T) {
	for _, tc := range []struct {
		Name      string
		Request   *http.Request
		WantIP    net.IP
		WantError bool
	}{
		{
			Name: "Defaults to RemoteAddr",
			Request: &http.Request{
				RemoteAddr: "10.1.2.3:1234",
			},
			WantIP: net.IPv4(10, 1, 2, 3),
		},
		{
			Name: "XFF",
			Request: &http.Request{
				RemoteAddr: "10.1.2.3:1234",
				Header: http.Header{
					"X-Forwarded-For": []string{"1.2.3.4"},
				},
			},
			WantIP: net.IPv4(1, 2, 3, 4),
		},
		{
			Name: "Chained XFF",
			Request: &http.Request{
				RemoteAddr: "10.1.2.3:1234",
				Header: http.Header{
					"X-Forwarded-For": []string{"1.2.3.4, 2.3.4.5, 3.4.5.6"},
				},
			},
			WantIP: net.IPv4(3, 4, 5, 6),
		},
		{
			Name: "Invalid IP in XFF",
			Request: &http.Request{
				RemoteAddr: "10.1.2.3:1234",
				Header: http.Header{
					"X-Forwarded-For": []string{"420.hello"},
				},
			},
			WantError: true,
		},
		{
			Name: "Emoji in XFF",
			Request: &http.Request{
				RemoteAddr: "10.1.2.3:1234",
				Header: http.Header{
					"X-Forwarded-For": []string{"🍷"},
				},
			},
			WantError: true,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			ip, err := clientIP(tc.Request)
			if (err != nil) != tc.WantError {
				t.Errorf("got error %v, want %v", err, tc.WantError)
			}
			if tc.WantIP != nil && !tc.WantIP.Equal(ip) {
				t.Errorf("got IP %v, want %v", ip, tc.WantIP)
			}
		})
	}
}

func TestHandler(t *testing.T) {
	helloHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello world"))
	})

	cases := []struct {
		name       string
		authorizer Authorizer
		req        *http.Request
		wantStatus int
		wantBody   string
	}{
		{
			name: "denied based on path",
			authorizer: AuthorizerFunc(func(r *http.Request) error {
				if r.URL.Path == "/denied" {
					return errors.New("denied")
				}
				return nil
			}),
			req: &http.Request{
				Method: "GET",
				URL: &url.URL{
					Path: "/denied",
				},
			},
			wantStatus: http.StatusForbidden,
			wantBody:   "denied",
		},
		{
			name: "allowed based on path",
			authorizer: AuthorizerFunc(func(r *http.Request) error {
				if r.URL.Path == "/denied" {
					return errors.New("denied")
				}
				return nil
			}),
			req: &http.Request{
				Method: "GET",
				URL: &url.URL{
					Path: "/allowed",
				},
			},
			wantStatus: http.StatusOK,
			wantBody:   "hello world",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			handler := httpPolicyHandler(helloHandler, tc.authorizer)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, tc.req)

			resp := rr.Result()
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("got status %v, want %v", resp.StatusCode, tc.wantStatus)
			}

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			} else if !strings.Contains(string(body), tc.wantBody) {
				t.Errorf("got body %v, want %v", string(body), tc.wantBody)
			}
		})
	}
}
