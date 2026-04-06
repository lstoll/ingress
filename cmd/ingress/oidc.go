package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"

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
	RequireGroup   string
}

func buildMiddlewareForHost(ctx context.Context, incomingHostname string, cfg oidcConfig) (func(http.Handler) http.Handler, error) {
	// TODO - do this per-request or something withe the inbound hostname? allowlist them though!
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
			h.ServeHTTP(w, r)
		})
	}

	refreshMw := func() error {
		refreshMu.Lock()
		defer refreshMu.Unlock()
		if time.Since(lastRefreshed) < middlewareRefreshInterval {
			return nil
		}
		clientID, clientSecret, err := oidcClientCredentials(ctx, cfg, incomingHostname, redirectURL)
		if err != nil {
			return err
		}
		omw, err := middleware.NewIDSSOHandlerFromDiscovery(ctx, nil, cfg.Issuer, clientID, clientSecret, redirectURL)
		if err != nil {
			return fmt.Errorf("oidc: from discovery: %w", err)
		}

		lastRefreshed = time.Now()
		currentMw = func(h http.Handler) http.Handler {
			return omw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				cl, ok := omw.IDClaimsFromContext(r.Context())
				if !ok {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}

				if cfg.RequireGroup != "" && !claimsHasGroup(cl, cfg.RequireGroup) {
					http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
					return
				}

				if cfg.UsernameHeader != "" {
					if username, err := cl.StringClaim("preferred_username"); err == nil && username != "" {
						r.Header.Set(cfg.UsernameHeader, username)
					}
				}
				if cfg.EmailHeader != "" {
					if email, err := cl.StringClaim("email"); err == nil && email != "" {
						r.Header.Set(cfg.EmailHeader, email)
					}
				}

				h.ServeHTTP(w, r)
			}))
		}

		return nil
	}

	// Prime middleware so we never serve with nil currentMw.
	if err := refreshMw(); err != nil {
		return nil, fmt.Errorf("oidc: initial middleware refresh: %w", err)
	}

	// Refresh middleware periodically (provider discovery, registration if used, then new handler).
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
			refreshMu.RLock()
			mw := currentMw
			refreshMu.RUnlock()
			if mw == nil {
				// Fallback: e.g. initial refresh failed after we started serving.
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

