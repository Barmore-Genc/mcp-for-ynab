package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestMintVerifyRoundTrip(t *testing.T) {
	s := NewSigner("secret")
	cred := s.Mint(Payload{Kind: KindAccess, ClientID: "c1", Scope: "ynab"}, AccessTTL)
	p, err := s.Verify(cred, KindAccess)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if p.ClientID != "c1" || p.Scope != "ynab" {
		t.Fatalf("payload round trip lost fields: %+v", p)
	}
}

func TestVerifyRejectsWrongKind(t *testing.T) {
	s := NewSigner("secret")
	cred := s.Mint(Payload{Kind: KindRefresh, ClientID: "c1"}, RefreshTTL)
	if _, err := s.Verify(cred, KindAccess); err == nil {
		t.Fatal("a refresh token verified as an access token")
	}
}

func TestVerifyRejectsOtherKey(t *testing.T) {
	cred := NewSigner("secret").Mint(Payload{Kind: KindAccess}, AccessTTL)
	if _, err := NewSigner("different").Verify(cred, KindAccess); err == nil {
		t.Fatal("a credential verified under a different key")
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	s := NewSigner("secret")
	cred := s.Mint(Payload{Kind: KindAccess, ClientID: "c1"}, AccessTTL)
	body, sig, _ := strings.Cut(cred, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(body)
	forged := base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(raw), `"c1"`, `"c2"`, 1)))
	if _, err := s.Verify(forged+"."+sig, KindAccess); err == nil {
		t.Fatal("a rewritten payload verified under the original signature")
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	s := NewSigner("secret")
	cred := s.Mint(Payload{Kind: KindCode}, -time.Second)
	if _, err := s.Verify(cred, KindCode); err == nil {
		t.Fatal("an expired code verified")
	}
}

// A client id has no expiry, so a connector registered long ago keeps working.
func TestClientIDDoesNotExpire(t *testing.T) {
	s := NewSigner("secret")
	cred := s.Mint(Payload{Kind: KindClient, RedirectURIs: []string{"https://x/cb"}}, 0)
	p, err := s.Verify(cred, KindClient)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(p.RedirectURIs) != 1 {
		t.Fatalf("redirect URIs lost: %+v", p)
	}
}

func TestRedeemIsOneShot(t *testing.T) {
	s := NewSigner("secret")
	p := Payload{ID: "abc", Expires: time.Now().Add(time.Minute).Unix()}
	if !s.Redeem(p) {
		t.Fatal("first redemption refused")
	}
	if s.Redeem(p) {
		t.Fatal("code redeemed twice")
	}
}

func TestVerifyS256(t *testing.T) {
	verifier := "a-verifier-of-reasonable-length-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if !VerifyS256(verifier, challenge) {
		t.Fatal("matching verifier rejected")
	}
	if VerifyS256("wrong", challenge) {
		t.Fatal("wrong verifier accepted")
	}
}
