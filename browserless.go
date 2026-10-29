package main

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	http "github.com/bogdanfinn/fhttp"
	"io"
	"math/big"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type VerificationProfile struct {
	UserAgent string                     `json:"userAgent"`
	JSA       map[string]json.RawMessage `json:"jsa"`
}

func rawInt(v json.RawMessage) (int, error) {
	var n int
	if json.Unmarshal(v, &n) == nil {
		return n, nil
	}
	var s string
	if json.Unmarshal(v, &s) == nil {
		return strconv.Atoi(s)
	}
	return 0, fmt.Errorf("invalid challenge integer")
}
func rawString(v json.RawMessage) string {
	var s string
	if json.Unmarshal(v, &s) == nil {
		return s
	}
	return string(v)
}
func solveChallenge(ctx context.Context, c map[string]json.RawMessage) (any, int64, error) {
	version, e := rawInt(c["challenge_version"])
	if e != nil {
		return nil, 0, e
	}
	timeout := 15000
	if v, e := rawInt(c["timeout"]); e == nil && v > 0 {
		timeout = min(v, 15000)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Millisecond)
	defer cancel()
	start := time.Now()
	if version == 1 {
		low, e := rawInt(c["low"])
		if e != nil {
			return nil, 0, e
		}
		high, e := rawInt(c["high"])
		if e != nil {
			return nil, 0, e
		}
		parts, e := rawInt(c["parts"])
		if e != nil {
			return nil, 0, e
		}
		target, ok := new(big.Int).SetString(rawString(c["result"]), 10)
		if !ok || low < 1 || high < low || high > 1000000 || parts < 1 || parts > 16 {
			return nil, 0, fail("Unsupported factor challenge bounds")
		}
		var visit func(int, int, *big.Int) ([]int, bool)
		visit = func(minimum, left int, remaining *big.Int) ([]int, bool) {
			for n := minimum; n <= high; n++ {
				if ctx.Err() != nil {
					return nil, false
				}
				q, r := new(big.Int), new(big.Int)
				q.QuoRem(remaining, big.NewInt(int64(n)), r)
				if r.Sign() != 0 {
					continue
				}
				if left == 1 {
					if q.Cmp(big.NewInt(1)) == 0 {
						return []int{n}, true
					}
					continue
				}
				if q.Sign() <= 0 {
					continue
				}
				if tail, ok := visit(n, left-1, q); ok {
					return append([]int{n}, tail...), true
				}
			}
			return nil, false
		}
		if answer, ok := visit(low, parts, target); ok {
			return answer, time.Since(start).Milliseconds(), nil
		}
		return nil, 0, fail("Factor challenge not solved within limits")
	}
	if version != 2 && version != 3 {
		return nil, 0, fail("Unknown challenge version")
	}
	salt := rawString(c["salt"])
	want := rawString(c["challenge"])
	algorithm := strings.ToUpper(rawString(c["algorithm"]))
	for n := 0; n < 1000000; n++ {
		if n%1024 == 0 && ctx.Err() != nil {
			return nil, 0, fail("Challenge timed out")
		}
		input := []byte(salt + strconv.Itoa(n))
		var hash []byte
		switch algorithm {
		case "SHA-256":
			h := sha256.Sum256(input)
			hash = h[:]
		case "SHA-384":
			h := sha512.Sum384(input)
			hash = h[:]
		case "SHA-512":
			h := sha512.Sum512(input)
			hash = h[:]
		case "SHA-1":
			h := sha1.Sum(input)
			hash = h[:]
		default:
			return nil, 0, fail("Unsupported challenge hash")
		}
		if version == 3 {
			l := len(hash)
			hash[l-1], hash[l-4] = hash[l-4], hash[l-1]
			hash[l-2], hash[l-3] = hash[l-3], hash[l-2]
		}
		if hex.EncodeToString(hash) == want {
			return n, time.Since(start).Milliseconds(), nil
		}
	}
	return nil, 0, fail("Challenge solution absent within server script's search limit")
}
func (m *Monitor) verificationRequest(ctx context.Context, method, endpoint string, body []byte, jar, ua string, readBody bool) ([]byte, error) {
	cs, e := readCookies(jar)
	if e != nil {
		return nil, e
	}
	req, e := http.NewRequestWithContext(ctx, method, endpoint, strings.NewReader(string(body)))
	if e != nil {
		return nil, e
	}
	req.Header = http.Header{"user-agent": {ua}, "accept": {"*/*"}, "accept-language": {"en-GB,en;q=0.9"}, "referer": {m.Config.buyURL()}, "sec-fetch-site": {"same-origin"}, "sec-fetch-mode": {"cors"}, "sec-fetch-dest": {"empty"}, http.HeaderOrderKey: {"user-agent", "accept", "content-type", "origin", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer", "accept-language", "cookie"}}
	if method == "POST" {
		req.Header.Set("content-type", "text/plain;charset=UTF-8")
		req.Header.Set("origin", "https://www.apple.com")
	}
	if ch := cookieHeader(cs, req.URL); ch != "" {
		req.Header.Set("cookie", ch)
	}
	res, e := m.Client.Do(req)
	if e != nil {
		return nil, fail("Verification connection failed")
	}
	defer res.Body.Close()
	retry := retrySeconds(res.Header.Get("retry-after"))
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 65536))
		_ = writeCookies(jar, mergeCookies(cs, res.Cookies(), req.URL))
		return nil, &CheckError{Message: fmt.Sprintf("Verification %s %s HTTP %d", method, req.URL.Path, res.StatusCode), Retry: retry, Server: retry > 0, Status: res.StatusCode, Response: b}
	}
	if e = writeCookies(jar, mergeCookies(cs, res.Cookies(), req.URL)); e != nil {
		return nil, e
	}
	if readBody {
		return io.ReadAll(io.LimitReader(res.Body, 2*1024*1024))
	}
	return nil, nil
}
func (m *Monitor) renewHTTP(ctx context.Context, jar, metadata, profilePath string, cold bool) (Stock, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	var profile VerificationProfile
	if e := readJSON(profilePath, &profile); e != nil {
		return nil, e
	}
	if profile.UserAgent == "" || len(profile.JSA) == 0 {
		return nil, fail("Missing captured verification profile")
	}
	var cookies []StoredCookie
	if !cold {
		var e error
		cookies, e = readCookies(m.path(".apple-cookies.txt"))
		if e != nil {
			return nil, e
		}
		filtered := cookies[:0]
		for _, c := range cookies {
			if !strings.HasPrefix(c.Name, "shld_") {
				filtered = append(filtered, c)
			}
		}
		cookies = filtered
	}
	if e := writeCookies(jar, cookies); e != nil {
		return nil, e
	}
	if e := saveJSON(metadata, Session{UserAgent: profile.UserAgent}); e != nil {
		return nil, e
	}
	// Bootstrap normal shop cookies through the product page. All changes remain
	// in the candidate jar until the final stock response validates the session.
	if _, e := m.verificationRequest(ctx, "GET", m.Config.productPage(), nil, jar, profile.UserAgent, true); e != nil {
		return nil, e
	}
	if cold {
		for _, endpoint := range []string{m.Config.shopURL() + "/beacon/atb", m.Config.shopURL() + "/dc"} {
			if _, e := m.verificationRequest(ctx, "GET", endpoint, nil, jar, profile.UserAgent, true); e != nil {
				return nil, e
			}
		}
	}
	query := url.Values{"jr": {rawString(profile.JSA["s"])}}
	if query.Get("jr") == "255" {
		query.Set("jr_r", rawString(profile.JSA["r"]))
	}
	endpoint := "https://www.apple.com/shop/shld/work/s3/q?" + query.Encode()
	var b []byte
	var e error
	for attempt := 0; attempt < 4; attempt++ {
		b, e = m.verificationRequest(ctx, "GET", endpoint, nil, jar, profile.UserAgent, true)
		if e == nil {
			break
		}
		ce, ok := e.(*CheckError)
		if !ok || ce.Status != 401 || ce.Server {
			return nil, e
		}
		var retry struct {
			Count    int `json:"retry_count"`
			Interval int `json:"retry_interval"`
		}
		if json.Unmarshal(ce.Response, &retry) != nil {
			return nil, e
		}
		fmt.Printf("Challenge retry: count=%d interval_ms=%d\n", retry.Count, retry.Interval)
		if attempt >= min(retry.Count, 3) {
			return nil, e
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(min(max(retry.Interval, 0), 15000)) * time.Millisecond):
		}
	}
	if e != nil {
		return nil, e
	}
	var challenge map[string]json.RawMessage
	if json.Unmarshal(b, &challenge) != nil {
		return nil, fail("Challenge response is not JSON")
	}
	shape := map[string]string{}
	for k, v := range challenge {
		var item any
		_ = json.Unmarshal(v, &item)
		shape[k] = fmt.Sprintf("%T", item)
	}
	version, _ := rawInt(challenge["challenge_version"])
	if e = saveJSON(m.path(".http-verification-diagnostic.json"), map[string]any{"at": stamp(), "fields": shape, "challengeVersion": version, "algorithm": rawString(challenge["algorithm"])}); e != nil {
		return nil, e
	}
	solution, took, e := solveChallenge(ctx, challenge)
	if e != nil {
		return nil, e
	}
	challenge["number"], _ = json.Marshal(solution)
	challenge["took"], _ = json.Marshal(took)
	challenge["flagskv"] = json.RawMessage(`{"patSkip":true}`)
	challenge["jsa"], _ = json.Marshal(profile.JSA)
	payload, _ := json.Marshal(challenge)
	if _, e = m.verificationRequest(ctx, "POST", endpoint, payload, jar, profile.UserAgent, false); e != nil {
		return nil, e
	}
	stock, e := m.fetch(ctx, jar, metadata)
	if e != nil {
		return nil, e
	}
	cookies, e = readCookies(jar)
	if e != nil {
		return nil, e
	}
	expiry := int64(0)
	for _, c := range cookies {
		if c.Name == "shld_bt_ck" {
			expiry = c.Expires
		}
	}
	if e = saveJSON(metadata, Session{UserAgent: profile.UserAgent, Expiry: float64(expiry)}); e != nil {
		return nil, e
	}
	return stock, nil
}
func (m *Monitor) probeHTTP(ctx context.Context, cold bool) error {
	if epoch() < m.Recovery.BlockedUntil {
		return fail("Apple cooldown active")
	}
	dir, e := os.MkdirTemp("", "iphone-http-renew-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(dir)
	stock, e := m.renewHTTP(ctx, dir+"/cookies", dir+"/metadata", m.path(".apple-verification-profile.json"), cold)
	if e != nil {
		return e
	}
	return printJSON(map[string]any{"at": stamp(), "browserless": true, "cold": cold, "stock": stock})
}

func (m *Monitor) renew(ctx context.Context) (Stock, error) {
	if m.Config.RenewalMode != "http" {
		return m.renewBrowser(ctx)
	}
	m.Recovery.LastAttempt = epoch()
	if e := m.persist(); e != nil {
		return nil, e
	}
	jar := m.path(".apple-cookies.http-candidate.txt")
	metadata := jar + ".json"
	defer os.Remove(jar)
	defer os.Remove(metadata)
	cold := false
	cookies, e := readCookies(m.path(".apple-cookies.txt"))
	if os.IsNotExist(e) {
		cold = true
	} else if e != nil {
		return nil, e
	}
	hasShopSession := false
	for _, c := range cookies {
		if c.Name == "as_pcts" && c.Value != "" && (c.Expires == 0 || c.Expires > time.Now().Unix()) {
			hasShopSession = true
		}
	}
	cold = cold || !hasShopSession
	stock, e := m.renewHTTP(ctx, jar, metadata, m.path(".apple-verification-profile.json"), cold)
	var rejected *CheckError
	if e != nil && !cold && errors.As(e, &rejected) && !rejected.Server && (rejected.Status == 401 || rejected.Session) {
		cold = true
		stock, e = m.renewHTTP(ctx, jar, metadata, m.path(".apple-verification-profile.json"), true)
	}
	diagnostic := map[string]any{"at": stamp(), "method": "http", "ok": e == nil, "cold": cold}
	if e != nil {
		diagnostic["error"] = e.Error()
	}
	if err := saveJSON(m.path(".session-diagnostic.direct.json"), diagnostic); err != nil {
		return nil, err
	}
	if e != nil {
		return nil, m.deferError(e)
	}
	if e = os.Rename(jar, m.path(".apple-cookies.txt")); e != nil {
		return nil, e
	}
	if e = os.Rename(metadata, m.path(".apple-session.json")); e != nil {
		return nil, e
	}
	m.LastRenewal = epoch()
	m.Warning = ""
	return stock, saveJSON(m.path(".session-renewal.direct.json"), map[string]any{"renewedAt": stamp(), "route": "direct", "method": "http"})
}
