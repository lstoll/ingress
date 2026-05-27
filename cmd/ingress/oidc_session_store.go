package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"lds.li/oauth2ext/middleware"
	"lds.li/oauth2ext/oidc"
	"lds.li/tinkrotate"
)

const (
	defaultOIDCSessionCookieName = "__Host-oidc-session"
	defaultOIDCSessionTTL        = 15 * time.Minute
)

type encryptedOIDCCookieSessionStore struct {
	aead       tinkrotate.ContextBoundAEAD
	cookieName string
	cookiePath string
	secure     bool
	sameSite   http.SameSite
}

type encryptedOIDCCookiePayload struct {
	ExpiresUnix int64                   `json:"exp"`
	Session     *middleware.SessionData `json:"session"`
}

func newEncryptedOIDCCookieSessionStore(aead tinkrotate.ContextBoundAEAD) *encryptedOIDCCookieSessionStore {
	return &encryptedOIDCCookieSessionStore{
		aead:       aead,
		cookieName: defaultOIDCSessionCookieName,
		cookiePath: "/",
		secure:     true,
		sameSite:   http.SameSiteLaxMode,
	}
}

func (s *encryptedOIDCCookieSessionStore) GetOIDCSession(r *http.Request) (*middleware.SessionData, error) {
	c, err := r.Cookie(s.cookieName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return &middleware.SessionData{}, nil
		}
		return nil, fmt.Errorf("getting oidc session cookie: %w", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil, fmt.Errorf("decoding oidc session cookie: %w", err)
	}
	plain, err := s.aead.WithContext(r.Context()).Decrypt(raw, []byte(s.cookieName))
	if err != nil {
		return nil, fmt.Errorf("decrypting oidc session cookie: %w", err)
	}
	var payload encryptedOIDCCookiePayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return nil, fmt.Errorf("unmarshaling oidc session cookie: %w", err)
	}
	if payload.ExpiresUnix > 0 && time.Now().After(time.Unix(payload.ExpiresUnix, 0)) {
		return &middleware.SessionData{}, nil
	}
	if payload.Session == nil {
		return &middleware.SessionData{}, nil
	}
	return payload.Session, nil
}

func (s *encryptedOIDCCookieSessionStore) SaveOIDCSession(w http.ResponseWriter, r *http.Request, d *middleware.SessionData) error {
	if d == nil || (d.Token == nil && len(d.Logins) == 0) {
		http.SetCookie(w, s.newCookie("", time.Time{}, true))
		return nil
	}

	exp := s.sessionExpiry(d)
	payload := encryptedOIDCCookiePayload{
		ExpiresUnix: exp.Unix(),
		Session:     d,
	}
	plain, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling oidc session payload: %w", err)
	}
	enc, err := s.aead.WithContext(r.Context()).Encrypt(plain, []byte(s.cookieName))
	if err != nil {
		return fmt.Errorf("encrypting oidc session payload: %w", err)
	}
	http.SetCookie(w, s.newCookie(base64.RawURLEncoding.EncodeToString(enc), exp, false))
	return nil
}

func (s *encryptedOIDCCookieSessionStore) sessionExpiry(d *middleware.SessionData) time.Time {
	now := time.Now()
	exp := now.Add(defaultOIDCSessionTTL)
	if d.Token != nil && d.Token.Token != nil && !d.Token.Token.Expiry.IsZero() {
		exp = d.Token.Token.Expiry
	}
	for _, l := range d.Logins {
		if l.Expires == 0 {
			continue
		}
		loginExp := time.Unix(int64(l.Expires), 0)
		if loginExp.After(exp) {
			exp = loginExp
		}
	}
	if exp.Before(now.Add(30 * time.Second)) {
		exp = now.Add(defaultOIDCSessionTTL)
	}
	return exp
}

func (s *encryptedOIDCCookieSessionStore) newCookie(value string, exp time.Time, deleteCookie bool) *http.Cookie {
	c := &http.Cookie{
		Name:     s.cookieName,
		Value:    value,
		Path:     s.cookiePath,
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: s.sameSite,
	}
	if deleteCookie {
		c.MaxAge = -1
		return c
	}
	ttl := int(time.Until(exp).Seconds())
	if ttl < 1 {
		ttl = 1
	}
	c.MaxAge = ttl
	return c
}

type oidcSessionStoreBuilder func(ctx context.Context, host string, cfg oidcConfig) (middleware.SessionStore, error)

func newTinkBackedOIDCSessionStoreBuilder(ps *tinkrotate.PrimitiveSource, keysetName string) oidcSessionStoreBuilder {
	return func(_ context.Context, _ string, _ oidcConfig) (middleware.SessionStore, error) {
		aead, err := ps.GetAEAD(keysetName)
		if err != nil {
			return nil, fmt.Errorf("getting oidc session AEAD: %w", err)
		}
		return newEncryptedOIDCCookieSessionStore(aead), nil
	}
}

func hasScope(scopes []string, wanted string) bool {
	for _, s := range scopes {
		if strings.EqualFold(strings.TrimSpace(s), wanted) {
			return true
		}
	}
	return false
}

func tokenHasRefreshToken(tok *oidc.TokenWithID) bool {
	if tok == nil || tok.Token == nil {
		return false
	}
	return strings.TrimSpace(tok.Token.RefreshToken) != ""
}
