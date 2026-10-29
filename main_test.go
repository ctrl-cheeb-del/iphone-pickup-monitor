package main

import (
	"context"
	"encoding/json"
	"errors"
	http "github.com/bogdanfinn/fhttp"
	nethttp "net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture() (Config, []byte) {
	c := Config{Products: map[string]string{"p1": "Phone"}, Stores: []string{"Manchester Arndale"}, ChatID: 1}
	return c, []byte(`{"body":{"content":{"pickupMessage":{"stores":[{"storeName":"Manchester Arndale","partsAvailability":{"p1":{"pickupDisplay":"unavailable"}}}]}}}}`)
}
func TestStrictStock(t *testing.T) {
	c, b := fixture()
	s, e := parseStock(b, c)
	if e != nil || len(s) != 1 || s["Manchester Arndale|p1"] {
		t.Fatal(s, e)
	}
	for _, bad := range []string{`{}`, strings.ReplaceAll(string(b), "unavailable", "not available"), strings.ReplaceAll(string(b), "Manchester Arndale", "Other")} {
		if _, e := parseStock([]byte(bad), c); e == nil {
			t.Fatal("accepted unknown response")
		}
	}
}
func TestCookiePersistenceAndScope(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cookies")
	cs := []StoredCookie{{Domain: ".apple.com", Path: "/uk", Name: "token", Value: strings.Repeat("x", 1000), Secure: true, HTTPOnly: true, Subdomains: true}}
	if e := writeCookies(p, cs); e != nil {
		t.Fatal(e)
	}
	got, e := readCookies(p)
	if e != nil || len(got) != 1 || got[0] != cs[0] {
		t.Fatal("cookie truncated", e)
	}
	stat, _ := os.Stat(p)
	if stat.Mode().Perm() != 0600 {
		t.Fatal("private permissions")
	}
	for _, raw := range []string{"http://www.apple.com/uk/shop", "https://badapple.com/uk", "https://www.apple.com/ukraine"} {
		u, _ := url.Parse(raw)
		if cookieHeader(got, u) != "" {
			t.Fatal("cookie scope leak", raw)
		}
	}
	u, _ := url.Parse("https://www.apple.com/uk/shop")
	if cookieHeader(got, u) == "" {
		t.Fatal("missing scoped cookie")
	}
}
func TestCookieDeletion(t *testing.T) {
	u, _ := url.Parse("https://www.apple.com/uk/shop/fulfillment-messages")
	cs := []StoredCookie{{Domain: ".apple.com", Path: "/", Name: "token", Value: "old", Subdomains: true}}
	merged := mergeCookies(cs, []*http.Cookie{{Name: "token", Domain: ".apple.com", Path: "/", MaxAge: -1}}, u)
	if len(merged) != 0 {
		t.Fatal("deleted cookie retained")
	}
}
func TestAtomicCookieCommit(t *testing.T) {
	c, body := fixture()
	for _, code := range []int{200, 429, 541} {
		t.Run(nethttp.StatusText(code), func(t *testing.T) {
			root := t.TempDir()
			srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
				if r.Header.Get("Cookie") != "token=old" {
					t.Errorf("wrong request cookie")
				}
				w.Header().Set("Set-Cookie", "token=new; Path=/")
				w.Header().Set("Retry-After", "1800")
				w.WriteHeader(code)
				w.Write(body)
			}))
			defer srv.Close()
			u, _ := url.Parse(srv.URL)
			jar := filepath.Join(root, "cookies")
			meta := filepath.Join(root, "meta")
			writeCookies(jar, []StoredCookie{{Domain: u.Hostname(), Path: "/", Name: "token", Value: "old"}})
			saveJSON(meta, Session{UserAgent: "test"})
			cl, e := newClient()
			if e != nil {
				t.Fatal(e)
			}
			defer cl.CloseIdleConnections()
			if cl.GetCookieJar() != nil {
				t.Fatal("automatic jar would bypass transactional cookies")
			}
			m := Monitor{Root: root, Client: cl, Config: c, Endpoint: srv.URL}
			_, e = m.fetch(context.Background(), jar, meta)
			got, _ := readCookies(jar)
			if code == 200 {
				if e != nil || got[0].Value != "new" {
					t.Fatal(e, got)
				}
			} else {
				var ce *CheckError
				if !errors.As(e, &ce) || !ce.Server || ce.Retry != 1800 || got[0].Value != "old" {
					t.Fatal("rejection corrupted session", e, got)
				}
			}
		})
	}
}
func TestMalformed200DoesNotCommitCookies(t *testing.T) {
	c, _ := fixture()
	root := t.TempDir()
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Set-Cookie", "token=new; Path=/")
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	jar := filepath.Join(root, "cookies")
	meta := filepath.Join(root, "meta")
	writeCookies(jar, []StoredCookie{{Domain: u.Hostname(), Path: "/", Name: "token", Value: "old"}})
	saveJSON(meta, Session{UserAgent: "test"})
	cl, _ := newClient()
	defer cl.CloseIdleConnections()
	m := Monitor{Config: c, Client: cl, Endpoint: srv.URL}
	if _, e := m.fetch(context.Background(), jar, meta); e == nil {
		t.Fatal("accepted malformed stock")
	}
	cs, _ := readCookies(jar)
	if cs[0].Value != "old" {
		t.Fatal("cookie changed")
	}
}
func TestDurableCooldown(t *testing.T) {
	root := t.TempDir()
	m := Monitor{Root: root}
	m.deferError(&CheckError{Message: "wait", Retry: 1800, Server: true})
	next := Monitor{Root: root}
	if e := readJSON(next.path(".session-recovery.json"), &next.Recovery); e != nil {
		t.Fatal(e)
	}
	if _, e := next.check(context.Background()); e == nil {
		t.Fatal("ignored cooldown")
	}
	if next.Recovery.BlockedUntil < epoch()+1700 {
		t.Fatal("lost cooldown")
	}
}
func TestExpiryScheduling(t *testing.T) {
	root := t.TempDir()
	expiry := time.Now().Unix() + 7200
	writeCookies(filepath.Join(root, ".apple-cookies.txt"), []StoredCookie{{Domain: ".apple.com", Path: "/", Name: "shld_bt_ck", Value: "x", Expires: expiry}})
	m := Monitor{Root: root}
	if m.nextRenewal() != float64(expiry-900) {
		t.Fatal("wrong expiry")
	}
}
func TestRestockAndFailedAlerts(t *testing.T) {
	c, _ := fixture()
	state := Stock{}
	key := "Manchester Arndale|p1"
	n := 0
	notify := func(string) error { n++; return nil }
	applyStock(c, Stock{key: true}, state, notify)
	applyStock(c, Stock{key: true}, state, notify)
	applyStock(c, Stock{key: false}, state, notify)
	applyStock(c, Stock{key: true}, state, notify)
	if n != 2 {
		t.Fatal(n)
	}
	state = Stock{}
	e := applyStock(c, Stock{key: true}, state, func(string) error { return errors.New("offline") })
	if e == nil || state[key] {
		t.Fatal("failed alert committed")
	}
}
func TestRetryDate(t *testing.T) {
	if retrySeconds("1800") != 1800 || retrySeconds("bad") != 0 {
		t.Fatal("invalid retry parse")
	}
	v := time.Now().Add(time.Hour).UTC().Format(nethttp.TimeFormat)
	if n := retrySeconds(v); n < 3590 || n > 3600 {
		t.Fatal(n)
	}
}
func TestPythonStateCompatibility(t *testing.T) {
	var r Recovery
	if e := json.Unmarshal([]byte(`{"lastAttempt": 1793133822.99,"blockedUntil": 0}`), &r); e != nil || r.LastAttempt == 0 {
		t.Fatal(e)
	}
	var c Config
	if e := json.Unmarshal([]byte(`{"telegram_chat_id":10000000001}`), &c); e != nil || c.ChatID != 10000000001 {
		t.Fatal(e)
	}
}

func TestProxyCredentialsAreURLSafe(t *testing.T) {
	p := filepath.Join(t.TempDir(), "proxy.json")
	saveJSON(p, map[string]string{"server": "http://proxy.example:80", "username": "user@zone", "password": "p:a/ss?#"})
	raw, e := proxyURL(p)
	if e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	pass, _ := u.User.Password()
	if u.User.Username() != "user@zone" || pass != "p:a/ss?#" || u.Host != "proxy.example:80" {
		t.Fatal("credentials not preserved")
	}
	saveJSON(p, map[string]string{"server": "file:///private", "password": "secret"})
	if _, e := proxyURL(p); e == nil || strings.Contains(e.Error(), "secret") {
		t.Fatal("invalid proxy not safely rejected")
	}
}
