package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Barmore-Genc/mcp-for-ynab/internal/oauth"
)

func registerClient(t *testing.T, ts *httptest.Server, redirect, name string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"redirect_uris": []string{redirect}, "client_name": name})
	resp, err := http.Post(ts.URL+"/register", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer resp.Body.Close()
	var out struct {
		ClientID string `json:"client_id"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.ClientID == "" {
		t.Fatalf("register returned %d and no client_id", resp.StatusCode)
	}
	return out.ClientID
}

// Someone who starts an OIDC sign-in themselves and sends the provider link to
// the owner must not receive a code: the owner's browser does not hold the
// cookie that the sign-in was bound to.
func TestOIDCCallbackRequiresTheBrowserThatStartedIt(t *testing.T) {
	idp := newFakeIDP(t)
	ts := newOIDCTestServer(t, idp.ts.URL, idpEmail)
	const attackerCB = "https://attacker.example/cb"
	clientID := registerClient(t, ts, attackerCB, "Claude")

	form := authorizeForm(clientID)
	form.Set("redirect_uri", attackerCB)
	form.Set("decision", "allow")
	lure, cookies := startAtProvider(t, ts, idp, form)
	if len(cookies) != 1 || !strings.HasPrefix(cookies[0].Name, "__Host-") ||
		!cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("binding cookie not set as a __Host- Secure HttpOnly Lax cookie: %+v", cookies)
	}

	resp := returnFromProvider(t, ts, lure, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("callback without the binding cookie returned %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Fatalf("callback without the binding cookie redirected to %q", loc)
	}

	forged := *cookies[0]
	forged.Value = oauth.RandomSecret()
	resp = returnFromProvider(t, ts, lure, []*http.Cookie{&forged})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("callback with a different cookie value returned %d", resp.StatusCode)
	}
}

// The binding cookie is removed once used, so it does not linger.
func TestOIDCCallbackClearsBindingCookie(t *testing.T) {
	idp := newFakeIDP(t)
	ts := newOIDCTestServer(t, idp.ts.URL)
	clientID := register(t, ts)
	form := authorizeForm(clientID)
	form.Set("decision", "allow")
	authURL, cookies := startAtProvider(t, ts, idp, form)
	resp := returnFromProvider(t, ts, authURL, cookies)
	codeFrom(t, resp)
	var cleared bool
	for _, c := range resp.Cookies() {
		if c.Name == cookies[0].Name && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("binding cookie not cleared: %v", resp.Header.Values("Set-Cookie"))
	}
}

// A loopback http origin cannot hold a Secure cookie, so the binding falls back
// to a plain cookie name there instead of breaking local use.
func TestOIDCBindingOnLoopbackHTTPOrigin(t *testing.T) {
	cfg := testConfig()
	cfg.Origin = "http://127.0.0.1:8080"
	srv := New(cfg, oauth.NewSigner(cfg.SigningKey), http.NotFoundHandler())
	if srv.secureCookies || strings.HasPrefix(srv.flowCookieName("x"), "__Host-") {
		t.Fatal("loopback http origin would set a cookie the browser drops")
	}
}

// The OIDC state travels through the provider and the browser in the clear, so
// it must not carry the upstream PKCE verifier or nonce.
func TestOIDCStateCarriesNoUpstreamSecrets(t *testing.T) {
	idp := newFakeIDP(t)
	ts := newOIDCTestServer(t, idp.ts.URL)
	clientID := register(t, ts)
	form := authorizeForm(clientID)
	form.Set("decision", "allow")
	authURL, _ := startAtProvider(t, ts, idp, form)
	q := authURL.Query()
	body, _, _ := strings.Cut(q.Get("state"), ".")
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("decode state: %v", err)
	}
	var fields map[string]any
	json.Unmarshal(raw, &fields)
	for _, k := range []string{"cv", "no"} {
		if _, ok := fields[k]; ok {
			t.Fatalf("state carries %q: %s", k, raw)
		}
	}
	if strings.Contains(string(raw), q.Get("nonce")) {
		t.Fatalf("state carries the nonce: %s", raw)
	}
}

func TestAuthorizeSubmitRefusesCrossSitePost(t *testing.T) {
	ts := newTestServer(t)
	clientID := register(t, ts)
	form := authorizeForm(clientID)
	form.Set("username", testUser)
	form.Set("password", testPass)
	form.Set("decision", "allow")

	post := func(headers map[string]string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/authorize", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := noRedirect().Do(req)
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		resp.Body.Close()
		return resp
	}

	for _, h := range []map[string]string{
		{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"},
		{"Origin": "https://evil.example"},
	} {
		if resp := post(h); resp.StatusCode != http.StatusForbidden || resp.Header.Get("Location") != "" {
			t.Fatalf("cross-site POST with %v returned %d, Location %q", h, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	// The public origin is trusted even when a proxy rewrites the Host header
	// and the browser sends no Sec-Fetch-Site.
	if resp := post(map[string]string{"Origin": "https://mcp.example"}); resp.StatusCode != http.StatusFound {
		t.Fatalf("same-origin POST returned %d", resp.StatusCode)
	}
	if resp := post(map[string]string{"Sec-Fetch-Site": "same-origin"}); resp.StatusCode != http.StatusFound {
		t.Fatalf("same-origin POST returned %d", resp.StatusCode)
	}
}

func TestPagesSendSecurityHeaders(t *testing.T) {
	ts := newTestServer(t)
	clientID := register(t, ts)
	for _, path := range []string{"/authorize?" + authorizeForm(clientID).Encode(), "/authorize", "/"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		resp.Body.Close()
		csp := resp.Header.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "frame-ancestors 'none'", "form-action 'self'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: CSP %q lacks %q", path, csp, want)
			}
		}
		if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("%s: X-Frame-Options %q", path, got)
		}
		if got := resp.Header.Get("Referrer-Policy"); got != "no-referrer" {
			t.Errorf("%s: Referrer-Policy %q", path, got)
		}
	}
}

// Browsers apply form-action to the redirect that follows a form submission,
// so the consent page must list where that redirect goes or the sign-in would
// be blocked after the password was accepted.
func TestConsentPageAllowsItsRedirectTargets(t *testing.T) {
	ts := newTestServer(t)
	clientID := register(t, ts)
	resp, err := http.Get(ts.URL + "/authorize?" + authorizeForm(clientID).Encode())
	if err != nil {
		t.Fatalf("get authorize: %v", err)
	}
	resp.Body.Close()
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' http://127.0.0.1:33418;") {
		t.Fatalf("CSP does not allow the client redirect: %q", csp)
	}

	idp := newFakeIDP(t)
	ots := newOIDCTestServer(t, idp.ts.URL)
	clientID = register(t, ots)
	resp, err = http.Get(ots.URL + "/authorize?" + authorizeForm(clientID).Encode())
	if err != nil {
		t.Fatalf("get authorize: %v", err)
	}
	resp.Body.Close()
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, idp.ts.URL) {
		t.Fatalf("CSP does not allow the provider %s: %q", idp.ts.URL, csp)
	}
}

// A registered redirect URI cannot inject directives into the CSP header.
func TestRegisterRefusesOddRedirectHosts(t *testing.T) {
	ts := newTestServer(t)
	for _, u := range []string{
		"https://a.example;script-src%20*/cb",
		"https://a.example/cb#frag",
		"https://user:pw@a.example/cb",
	} {
		body, _ := json.Marshal(map[string]any{"redirect_uris": []string{u}})
		resp, err := http.Post(ts.URL+"/register", "application/json", strings.NewReader(string(body)))
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s registered with status %d", u, resp.StatusCode)
		}
	}
}

// The name is chosen by whoever registers, so the consent page leads with the
// host access is sent to, and the name is cleaned and labelled as the app's.
func TestConsentPageShowsDestinationAndCleansName(t *testing.T) {
	ts := newTestServer(t)
	name := "Claude‮\x07 " + strings.Repeat("x", 300)
	clientID := registerClient(t, ts, "https://attacker.example/cb", name)
	form := authorizeForm(clientID)
	form.Set("redirect_uri", "https://attacker.example/cb")
	resp, err := http.Get(ts.URL + "/authorize?" + form.Encode())
	if err != nil {
		t.Fatalf("get authorize: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	body := string(raw)
	if !strings.Contains(body, "<strong>attacker.example</strong>") {
		t.Fatalf("destination host not shown: %s", body)
	}
	if strings.Contains(body, "‮") || strings.Contains(body, "\x07") {
		t.Fatal("control characters from the client name reached the page")
	}
	if !strings.Contains(body, "Name given by the app: Claude "+strings.Repeat("x", 93)+"</p>") {
		t.Fatalf("client name not cleaned, capped and labelled: %s", body)
	}
}

// Anyone can register a client with any https redirect, so a malformed request
// must not bounce the browser there.
func TestAuthorizeErrorsDoNotRedirect(t *testing.T) {
	ts := newTestServer(t)
	clientID := registerClient(t, ts, "https://evil.example/phish", "x")
	for _, q := range []url.Values{
		{"client_id": {clientID}, "redirect_uri": {"https://evil.example/phish"}},
		{"client_id": {clientID}, "redirect_uri": {"https://evil.example/phish"}, "response_type": {"token"}},
		{"client_id": {clientID}, "redirect_uri": {"https://evil.example/phish"}, "response_type": {"code"}, "state": {"s"}},
	} {
		resp, err := noRedirect().Get(ts.URL + "/authorize?" + q.Encode())
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
			t.Fatalf("%v: status %d, Location %q", q, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
}

func guess(t *testing.T, ts *httptest.Server, clientID string, i int, xff string) int {
	t.Helper()
	form := authorizeForm(clientID)
	form.Set("username", testUser)
	form.Set("password", fmt.Sprintf("guess-%d", i))
	form.Set("decision", "allow")
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	resp, err := noRedirect().Do(req)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// Without a trusted proxy, X-Forwarded-For is the caller's own claim and must
// not give it a fresh allowance per value.
func TestLimiterIgnoresForwardedForFromUntrustedPeer(t *testing.T) {
	ts := newTestServer(t)
	clientID := register(t, ts)
	evaluated := 0
	for i := range 50 {
		if guess(t, ts, clientID, i, fmt.Sprintf("10.0.%d.%d", i/250, i%250)) != http.StatusTooManyRequests {
			evaluated++
		}
	}
	if evaluated != maxAttempts {
		t.Fatalf("%d guesses evaluated with rotating X-Forwarded-For, want %d", evaluated, maxAttempts)
	}
}

// Behind a trusted proxy each forwarded address has its own allowance, but the
// server-wide cap still bounds the total.
func TestLimiterGlobalCapBehindTrustedProxy(t *testing.T) {
	cfg := testConfig()
	cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	ts := serve(t, cfg)
	clientID := register(t, ts)
	evaluated := 0
	for i := range 50 {
		if guess(t, ts, clientID, i, fmt.Sprintf("203.0.113.%d", i)) != http.StatusTooManyRequests {
			evaluated++
		}
	}
	if evaluated != maxGlobalAttempts {
		t.Fatalf("%d guesses evaluated from distinct addresses, want %d", evaluated, maxGlobalAttempts)
	}
}

func TestClientAddr(t *testing.T) {
	s := &Server{}
	s.cfg.TrustedProxies = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("fd00::/8"),
	}
	cases := []struct {
		remote, xff, want string
	}{
		{"198.51.100.7:4000", "1.2.3.4", "198.51.100.7"},
		{"10.0.0.2:4000", "1.2.3.4", "1.2.3.4"},
		{"10.0.0.2:4000", "6.6.6.6, 1.2.3.4", "1.2.3.4"},
		{"10.0.0.2:4000", "6.6.6.6, 1.2.3.4, 10.0.0.3", "1.2.3.4"},
		{"10.0.0.2:4000", "garbage, 10.0.0.3", "10.0.0.3"},
		{"10.0.0.2:4000", "", "10.0.0.2"},
		{"[::ffff:198.51.100.7]:4000", "", "198.51.100.7"},
		{"[fd00::1]:4000", "2001:db8:1:2:3:4:5:6", "2001:db8:1:2::"},
		{"[2001:db8:1:2::9]:4000", "", "2001:db8:1:2::"},
		{"10.0.0.2:4000", "1.2.3.4:5678", "1.2.3.4"},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodPost, "/authorize", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := s.clientAddr(r); got != netip.MustParseAddr(c.want) {
			t.Errorf("remote %s, XFF %q: got %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
}

func TestLimiterWindowAndSweep(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newLimiter()
	l.now = func() time.Time { return now }
	a := netip.MustParseAddr("192.0.2.1")
	for range maxAttempts {
		if !l.allow(a) {
			t.Fatal("refused within the allowance")
		}
	}
	if l.allow(a) {
		t.Fatal("allowed past the allowance")
	}
	now = now.Add(attemptWindow + time.Second)
	if !l.allow(netip.MustParseAddr("192.0.2.2")) {
		t.Fatal("new caller refused after the window")
	}
	if _, ok := l.attempts[a]; ok {
		t.Fatal("expired entry not swept")
	}
	if !l.allow(a) {
		t.Fatal("caller still refused after the window")
	}
}

// The map is bounded even if the global cap were not; a full map refuses new
// callers rather than forgetting ones being slowed down.
func TestLimiterMapIsBounded(t *testing.T) {
	l := newLimiter()
	for i := range maxTracked {
		l.attempts[netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})] = attempt{count: 1, until: time.Now().Add(time.Hour)}
	}
	l.nextSweep = time.Now().Add(time.Hour)
	if l.allow(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("new caller admitted to a full map")
	}
	if len(l.attempts) != maxTracked {
		t.Fatalf("map grew to %d", len(l.attempts))
	}
}

func TestOAuthBodiesAreBounded(t *testing.T) {
	ts := newTestServer(t)
	big := `{"redirect_uris":["https://a.example/cb"],"client_name":"` + strings.Repeat("x", 100<<10) + `"}`
	resp, err := http.Post(ts.URL+"/register", "application/json", strings.NewReader(big))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized registration returned %d", resp.StatusCode)
	}
}

func refresh(t *testing.T, ts *httptest.Server, clientID, token string) (*http.Response, map[string]any) {
	t.Helper()
	return exchange(t, ts, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {token},
		"client_id":     {clientID},
	})
}

// Refreshing carries the original sign-in time forward, so a refresh token
// cannot keep a session alive past MaxSessionAge.
func TestRefreshStopsAfterMaxSessionAge(t *testing.T) {
	ts := newTestServer(t)
	clientID := register(t, ts)
	signer := oauth.NewSigner(testSigningKey)

	code := codeFrom(t, signIn(t, ts, clientID, testUser, testPass))
	_, out := exchange(t, ts, codeForm(clientID, code))
	first, err := signer.Verify(out["refresh_token"].(string), oauth.KindRefresh)
	if err != nil || first.AuthTime == 0 {
		t.Fatalf("refresh token carries no sign-in time: %+v %v", first, err)
	}
	resp, out := refresh(t, ts, clientID, out["refresh_token"].(string))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh failed: %v", out)
	}
	second, _ := signer.Verify(out["refresh_token"].(string), oauth.KindRefresh)
	if second.AuthTime != first.AuthTime {
		t.Fatalf("refresh reset the sign-in time: %d -> %d", first.AuthTime, second.AuthTime)
	}

	old := time.Now().Add(-oauth.MaxSessionAge - time.Hour).Unix()
	for name, p := range map[string]oauth.Payload{
		"too old":      {Kind: oauth.KindRefresh, ClientID: clientID, AuthTime: old},
		"no auth time": {Kind: oauth.KindRefresh, ClientID: clientID},
	} {
		tok := signer.Mint(p, oauth.RefreshTTL)
		if resp, out := refresh(t, ts, clientID, tok); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: refresh accepted: %v", name, out)
		}
	}

	// Near the end of the session, the new tokens do not outlive it.
	late := time.Now().Add(-oauth.MaxSessionAge + 10*time.Minute).Unix()
	tok := signer.Mint(oauth.Payload{Kind: oauth.KindRefresh, ClientID: clientID, AuthTime: late}, oauth.RefreshTTL)
	resp, out = refresh(t, ts, clientID, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh near the end refused: %v", out)
	}
	if exp := out["expires_in"].(float64); exp > 600 {
		t.Fatalf("access token outlives the session: expires_in %v", exp)
	}
	p, _ := signer.Verify(out["refresh_token"].(string), oauth.KindRefresh)
	if p.ExpiresAt().After(time.Unix(late, 0).Add(oauth.MaxSessionAge)) {
		t.Fatal("refresh token outlives the session")
	}
}

// An email only matches the allowlist when the provider has verified it.
func TestOIDCIgnoresUnverifiedEmail(t *testing.T) {
	for _, verified := range []any{false, "false", nil} {
		idp := newFakeIDP(t)
		idp.emailVerified = verified
		ts := newOIDCTestServer(t, idp.ts.URL, idpEmail)
		clientID := register(t, ts)
		loc := signInThroughProvider(t, ts, idp, clientID).Header.Get("Location")
		if !strings.Contains(loc, "error=access_denied") {
			t.Fatalf("email_verified=%v: unverified email accepted, redirected to %q", verified, loc)
		}
	}

	idp := newFakeIDP(t)
	idp.emailVerified = "true"
	ts := newOIDCTestServer(t, idp.ts.URL, idpEmail)
	clientID := register(t, ts)
	codeFrom(t, signInThroughProvider(t, ts, idp, clientID))
}
