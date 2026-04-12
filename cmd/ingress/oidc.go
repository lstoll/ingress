package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"lds.li/oauth2ext/claims"
	"lds.li/oauth2ext/middleware"
	"lds.li/oauth2ext/oidcclientreg"
	"lds.li/oauth2ext/provider"
)

const middlewareRefreshInterval = 24 * time.Hour

type oidcConfig struct {
	Issuer string

	// If set, ingress strips this header from inbound requests before auth,
	// then sets it from verified claims for upstream.
	UsernameHeader string
	EmailHeader    string
	NameHeader     string
	BypassPatterns []string
	RequireGroup   string

	ClientID     string
	ClientSecret string

	AllowUnauthenticated bool
	LoginPath            string
	LogoutPath           string
}

func buildMiddlewareForHost(ctx context.Context, incomingHostname string, cfg oidcConfig) (func(http.Handler) http.Handler, error) {
	redirectURL := "https://" + incomingHostname + "/.ingress/oidc-callback"

	var (
		lastRefreshed time.Time
		currentMw     func(http.Handler) http.Handler
		refreshMu     sync.RWMutex
	)

	withInboundHeaderStrip := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.UsernameHeader != "" {
				r.Header.Del(cfg.UsernameHeader)
			}
			if cfg.EmailHeader != "" {
				r.Header.Del(cfg.EmailHeader)
			}
			if cfg.NameHeader != "" {
				r.Header.Del(cfg.NameHeader)
			}
			h.ServeHTTP(w, r)
		})
	}

	buildMw := func(clientID, clientSecret string) (func(http.Handler) http.Handler, error) {
		omw, err := middleware.NewIDSSOHandlerFromDiscovery(ctx, nil, cfg.Issuer, clientID, clientSecret, redirectURL)
		if err != nil {
			return nil, fmt.Errorf("oidc: from discovery: %w", err)
		}
		omw.AllowUnauthenticated = cfg.AllowUnauthenticated

		return func(h http.Handler) http.Handler {
			return omw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if cfg.LoginPath != "" && r.URL.Path == cfg.LoginPath {
					omw.ServeLogin(w, r, safeRedirectTarget(r, cfg.LoginPath))
					return
				}
				if cfg.LogoutPath != "" && r.URL.Path == cfg.LogoutPath {
					omw.ServeLogout(w, r, safeRedirectTarget(r, cfg.LogoutPath))
					http.Redirect(w, r, safeRedirectTarget(r, cfg.LogoutPath), http.StatusFound)
					return
				}

				cl, ok := omw.IDClaimsFromContext(r.Context())
				if !ok {
					slog.Debug("oidc: request unauthenticated", "hostname", incomingHostname)
					if cfg.AllowUnauthenticated {
						h.ServeHTTP(w, r)
						return
					}
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}

				if cfg.RequireGroup != "" && !claimsHasGroup(cl, cfg.RequireGroup) {
					slog.Warn("oidc: request denied, required group missing", "hostname", incomingHostname, "required_group", cfg.RequireGroup)
					http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
					return
				}

				if cfg.UsernameHeader != "" {
					if username, err := cl.PreferredUsername(); err == nil && username != "" {
						r.Header.Set(cfg.UsernameHeader, username)
					}
				}
				if cfg.EmailHeader != "" {
					if email, err := cl.Email(); err == nil && email != "" {
						r.Header.Set(cfg.EmailHeader, email)
					}
				}
				if cfg.NameHeader != "" {
					if name, err := cl.Name(); err == nil && name != "" {
						r.Header.Set(cfg.NameHeader, name)
					}
				}

				slog.Debug("oidc: request authenticated", "hostname", incomingHostname, cfg.UsernameHeader, r.Header.Get(cfg.UsernameHeader), cfg.EmailHeader, r.Header.Get(cfg.EmailHeader), cfg.NameHeader, r.Header.Get(cfg.NameHeader))

				h.ServeHTTP(w, r)
			}))
		}, nil
	}

	refreshMw := func() error {
		refreshMu.Lock()
		defer refreshMu.Unlock()
		if time.Since(lastRefreshed) < middlewareRefreshInterval {
			return nil
		}
		slog.Info("oidc: refreshing middleware", "hostname", incomingHostname, "issuer", cfg.Issuer)

		var (
			clientID     = cfg.ClientID
			clientSecret = cfg.ClientSecret
			err          error
		)

		if clientID == "" || clientSecret == "" {
			// Always re-register: middleware construction doesn't validate
			// credentials (they're only used at token exchange time), so we
			// can't detect stale creds by retrying the build.
			clientID, clientSecret, err = oidcClientCredentials(ctx, cfg, incomingHostname, redirectURL)
			if err != nil {
				return err
			}
		}

		mw, err := buildMw(clientID, clientSecret)
		if err != nil {
			return err
		}

		lastRefreshed = time.Now()
		currentMw = mw
		return nil
	}

	if err := refreshMw(); err != nil {
		return nil, fmt.Errorf("oidc: initial middleware refresh: %w", err)
	}

	go func() {
		ticker := time.NewTicker(middlewareRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := refreshMw(); err != nil {
					slog.Error("oidc: background middleware refresh failed", "hostname", incomingHostname, "error", err)
				}
			}
		}
	}()

	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, p := range cfg.BypassPatterns {
				if strings.HasPrefix(r.URL.Path, p) {
					withInboundHeaderStrip(h).ServeHTTP(w, r)
					return
				}
			}

			refreshMu.RLock()
			mw := currentMw
			refreshMu.RUnlock()
			if mw == nil {
				if err := refreshMw(); err != nil {
					slog.Error("oidc: failed to refresh middleware", "error", err)
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				refreshMu.RLock()
				mw = currentMw
				refreshMu.RUnlock()
				if mw == nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
			}
			withInboundHeaderStrip(mw(h)).ServeHTTP(w, r)
		})
	}, nil
}

// oidcClientCredentials returns dynamic registration credentials.
func oidcClientCredentials(ctx context.Context, cfg oidcConfig, clientName, redirectURL string) (clientID, clientSecret string, err error) {
	p, err := provider.DiscoverOIDCProvider(ctx, cfg.Issuer)
	if err != nil {
		return "", "", fmt.Errorf("oidc: discover: %w", err)
	}
	regResp, err := registerOIDCClient(ctx, clientName, p, []string{redirectURL})
	if err != nil {
		return "", "", fmt.Errorf("oidc: register client: %w", err)
	}
	slog.Info("oidc: registered client", "client_id", regResp.ClientID)
	return regResp.ClientID, regResp.ClientSecret, nil
}

// registerOIDCClient performs dynamic client registration with the OIDC provider
func registerOIDCClient(ctx context.Context, clientName string, prov *provider.Provider, redirectURIs []string) (*oidcclientreg.ClientRegistrationResponse, error) {
	// Create registration request
	request := &oidcclientreg.ClientRegistrationRequest{
		ClientName:      fmt.Sprintf("ingress-%s", clientName),
		RedirectURIs:    redirectURIs,
		ApplicationType: "web",
		ResponseTypes:   []string{"code"},
		GrantTypes:      []string{"authorization_code"},
	}

	oidcMetadata, ok := prov.Metadata.(*provider.OIDCProviderMetadata)
	if !ok {
		return nil, fmt.Errorf("provider metadata is not an OIDC provider metadata")
	}

	if slices.Contains(oidcMetadata.IDTokenSigningAlgValuesSupported, "ES256") {
		request.IDTokenSignedResponseAlg = "ES256"
	}

	response, err := oidcclientreg.RegisterWithProvider(ctx, prov, request)
	if err != nil {
		return nil, fmt.Errorf("failed to register client: %w", err)
	}

	return response, nil
}

func claimsHasGroup(cl *claims.VerifiedID, required string) bool {
	groups, err := cl.ArrayClaim("groups")
	if err != nil || groups == nil {
		return false
	}
	for _, g := range groups {
		if gs, ok := g.(string); ok && gs == required {
			return true
		}
	}
	return false
}

// maxPathReturnToLen matches oauth2ext/middleware.sanitizeReturnTo.
const maxPathReturnToLen = 8192

// sanitizePathReturnTo returns a safe in-app redirect target: path-absolute,
// optional query, no scheme/host, no fragment. Invalid input falls back to "/".
// (Same rules as lds.li/oauth2ext/middleware.sanitizeReturnTo, which is not exported.)
func sanitizePathReturnTo(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "/"
	}
	if len(s) > maxPathReturnToLen {
		return "/"
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return "/"
		}
	}
	if strings.Contains(s, "#") {
		return "/"
	}

	pathPart, _, hasQuery := strings.Cut(s, "?")
	if strings.Contains(pathPart, "://") || strings.HasPrefix(pathPart, "//") {
		return "/"
	}
	if strings.Contains(pathPart, `\`) {
		return "/"
	}
	if !strings.HasPrefix(pathPart, "/") {
		return "/"
	}
	if hasQuery {
		for _, c := range s[len(pathPart)+1:] {
			if unicode.IsControl(c) {
				return "/"
			}
		}
	}

	u, err := url.Parse(s)
	if err != nil {
		return "/"
	}
	if u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return "/"
	}
	return s
}

// safeRedirectTarget reads ?redirect= (sanitized in-app URL), default "/".
// avoidPath is never returned so login/logout handlers do not redirect to themselves.
// For login, an explicit target is required: an empty returnTo in ServeLogin makes
// oauth2ext use the current request URI and causes a post-callback redirect loop.
func safeRedirectTarget(r *http.Request, avoidPath string) string {
	raw := strings.TrimSpace(r.URL.Query().Get("redirect"))
	if raw == "" {
		return "/"
	}
	s := sanitizePathReturnTo(raw)
	if avoidPath != "" && (s == avoidPath || strings.HasPrefix(s, avoidPath+"?")) {
		return "/"
	}
	return s
}
