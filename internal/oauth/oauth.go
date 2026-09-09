// Package oauth is the OAuth 2.1 authorization server this container runs for
// its own MCP endpoint. It exists because the connector UIs that people add MCP
// servers to (Claude's, Claude Code's) offer an OAuth flow and no field for a
// static bearer token, so a server that only wants one password still has to
// speak the whole ceremony.
//
// Every credential it issues — client id, authorization code, access token,
// refresh token — is a self-describing string signed with one HMAC key, so the
// server keeps no database and no volume. The container can be restarted or
// replaced without anyone re-authorizing, and the only state held in memory is
// a set of already-redeemed authorization codes, which each expire a minute
// after they are minted.
package oauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Credential lifetimes. The authorization code only has to survive the redirect
// back and the immediate exchange. The access token is an hour so an agent
// mid-conversation is not re-authorizing; the refresh token is 30 days so a
// connector left alone over a holiday still comes back without a browser.
const (
	CodeTTL    = time.Minute
	AccessTTL  = time.Hour
	RefreshTTL = 30 * 24 * time.Hour
)

// Credential kinds, carried in the payload so a token of one kind can never be
// presented as another.
const (
	KindClient  = "client"
	KindCode    = "code"
	KindAccess  = "access"
	KindRefresh = "refresh"
)

var ErrInvalid = errors.New("invalid credential")

// Payload is what a credential says about itself. Which fields are meaningful
// depends on Kind: a client carries its redirect URIs and name, a code carries
// the PKCE challenge and the redirect it was issued against, and the tokens
// carry only the client they belong to.
type Payload struct {
	Kind         string   `json:"k"`
	ID           string   `json:"i"`
	ClientID     string   `json:"c,omitempty"`
	ClientName   string   `json:"n,omitempty"`
	RedirectURIs []string `json:"r,omitempty"`
	RedirectURI  string   `json:"u,omitempty"`
	Challenge    string   `json:"h,omitempty"`
	Scope        string   `json:"s,omitempty"`
	Expires      int64    `json:"e"`
}

func (p Payload) ExpiresAt() time.Time { return time.Unix(p.Expires, 0) }

// Signer mints and verifies credentials under one key.
type Signer struct {
	key []byte

	mu   sync.Mutex
	used map[string]int64
}

// NewSigner derives the signing key from secret. Two servers started with the
// same secret mint interchangeable credentials, which is what lets a container
// be replaced in place; changing the secret invalidates everything at once.
func NewSigner(secret string) *Signer {
	sum := sha256.Sum256([]byte("mcp-for-ynab/oauth\x00" + secret))
	return &Signer{key: sum[:], used: map[string]int64{}}
}

// Mint signs p, filling in its id and expiry, and returns the credential string.
func (s *Signer) Mint(p Payload, ttl time.Duration) string {
	p.ID = RandomID()
	p.Expires = time.Now().Add(ttl).Unix()
	body, err := json.Marshal(p)
	if err != nil {
		// Payload is a fixed struct of strings and ints; marshalling it cannot
		// fail for any input this package constructs.
		panic(fmt.Sprintf("oauth: marshal payload: %v", err))
	}
	b := base64.RawURLEncoding.EncodeToString(body)
	return b + "." + base64.RawURLEncoding.EncodeToString(s.mac(b))
}

// Verify checks the signature, the expiry and the kind, and returns the payload.
// A credential that fails any of these is ErrInvalid without saying which,
// because the difference is only useful to someone probing.
func (s *Signer) Verify(cred, kind string) (Payload, error) {
	b, sig, ok := strings.Cut(cred, ".")
	if !ok {
		return Payload{}, ErrInvalid
	}
	want, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(want, s.mac(b)) {
		return Payload{}, ErrInvalid
	}
	body, err := base64.RawURLEncoding.DecodeString(b)
	if err != nil {
		return Payload{}, ErrInvalid
	}
	var p Payload
	if err := json.Unmarshal(body, &p); err != nil {
		return Payload{}, ErrInvalid
	}
	if p.Kind != kind {
		return Payload{}, ErrInvalid
	}
	// A client id is a naming credential rather than a session, so it does not
	// expire: a connector registered months ago should keep working.
	if kind != KindClient && time.Now().After(p.ExpiresAt()) {
		return Payload{}, ErrInvalid
	}
	return p, nil
}

func (s *Signer) mac(b string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(b))
	return m.Sum(nil)
}

// Redeem records that a one-time credential has been used and reports whether
// this was the first time. Only authorization codes go through it, so the map
// holds at most the codes minted in the last CodeTTL and is swept on every call.
func (s *Signer) Redeem(p Payload) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	for id, exp := range s.used {
		if exp < now {
			delete(s.used, id)
		}
	}
	if _, seen := s.used[p.ID]; seen {
		return false
	}
	s.used[p.ID] = p.Expires
	return true
}

// VerifyS256 reports whether verifier hashes to challenge under PKCE's S256
// method. Only S256 is accepted anywhere in the flow, so there is no plain
// branch; the compare is constant-time so a mismatch does not leak how much of
// the challenge matched.
func VerifyS256(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(want), []byte(challenge)) == 1
}

// RandomID returns 128 bits of entropy as base64url.
func RandomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("oauth: read random: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
