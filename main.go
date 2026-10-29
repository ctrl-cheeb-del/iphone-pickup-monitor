package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

const profileName = "chrome_152"

type Config struct {
	Country         string            `json:"country,omitempty"`
	Label           string            `json:"label,omitempty"`
	ProductPage     string            `json:"product_page,omitempty"`
	RetailProxyFile string            `json:"retail_proxy_file,omitempty"`
	StockEndpoint   string            `json:"stock_endpoint"`
	RenewalMode     string            `json:"renewal_mode"`
	Postcode        string            `json:"postcode"`
	Products        map[string]string `json:"products"`
	Stores          []string          `json:"stores"`
	Interval        int               `json:"interval_seconds"`
	ChatID          int64             `json:"telegram_chat_id"`
}

// shopURL is the Apple Store root for the configured storefront, UK by default.
func (c Config) shopURL() string {
	country := c.Country
	if country == "" {
		country = "uk"
	}
	return "https://www.apple.com/" + country + "/shop"
}
func (c Config) buyURL() string { return c.shopURL() + "/buy-iphone/iphone-duo" }

// productPage is the page loaded to bootstrap a shop session and its verification.
func (c Config) productPage() string {
	if c.ProductPage != "" {
		return c.ProductPage
	}
	if c.Country == "" || c.Country == "uk" {
		return c.buyURL() + "/7.6-inch-display-256gb-star-white"
	}
	return c.buyURL()
}

// name distinguishes outage messages when several monitors share a chat.
func (c Config) name() string {
	if c.Label == "" {
		return "iPhone monitor"
	}
	return "iPhone monitor (" + c.Label + ")"
}

type Stock map[string]bool
type Session struct {
	UserAgent string  `json:"userAgent"`
	Expiry    float64 `json:"verificationExpiry"`
}
type Recovery struct {
	LastAttempt  float64 `json:"lastAttempt"`
	BlockedUntil float64 `json:"blockedUntil"`
}
type CheckError struct {
	Status   int
	Response []byte
	Message  string
	Retry    float64
	Session  bool
	Server   bool
}

func (e *CheckError) Error() string { return e.Message }
func fail(message string) error     { return &CheckError{Message: message} }
func epoch() float64                { return float64(time.Now().UnixMilli()) / 1000 }
func stamp() string                 { return time.Now().UTC().Format(time.RFC3339) }
func readJSON(p string, v any) error {
	b, e := os.ReadFile(p)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}
func atomicWrite(p string, b []byte) error {
	f, e := os.CreateTemp(filepath.Dir(p), ".write-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(f.Name(), p)
}
func saveJSON(p string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return atomicWrite(p, append(b, '\n'))
}
func keys[V any](m map[string]V) []string {
	a := make([]string, 0, len(m))
	for k := range m {
		a = append(a, k)
	}
	sort.Strings(a)
	return a
}
func retrySeconds(v string) float64 {
	if n, e := strconv.ParseFloat(v, 64); e == nil && !math.IsNaN(n) && !math.IsInf(n, 0) {
		return max(0, n)
	}
	if t, e := http.ParseTime(v); e == nil {
		return max(0, time.Until(t).Seconds())
	}
	return 0
}

type StoredCookie struct {
	Domain, Path, Name, Value    string
	Secure, HTTPOnly, Subdomains bool
	Expires                      int64
}

func readCookies(p string) ([]StoredCookie, error) {
	f, e := os.Open(p)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var out []StoredCookie
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 4096), 1024*1024)
	for s.Scan() {
		line := s.Text()
		ho := strings.HasPrefix(line, "#HttpOnly_")
		if strings.HasPrefix(line, "#") && !ho || line == "" {
			continue
		}
		fields := strings.Split(strings.TrimPrefix(line, "#HttpOnly_"), "\t")
		if len(fields) != 7 {
			return nil, fail("Invalid cookie file")
		}
		exp, e := strconv.ParseInt(fields[4], 10, 64)
		if e != nil {
			return nil, fail("Invalid cookie expiry")
		}
		out = append(out, StoredCookie{fields[0], fields[2], fields[5], fields[6], fields[3] == "TRUE", ho, fields[1] == "TRUE", exp})
	}
	return out, s.Err()
}
func writeCookies(p string, cookies []StoredCookie) error {
	var b strings.Builder
	b.WriteString("# Netscape HTTP Cookie File\n")
	for _, c := range cookies {
		if strings.ContainsAny(c.Domain+c.Path+c.Name+c.Value, "\r\n\t") {
			return fail("Invalid cookie characters")
		}
		d := c.Domain
		if c.HTTPOnly {
			d = "#HttpOnly_" + d
		}
		tf := func(v bool) string {
			if v {
				return "TRUE"
			}
			return "FALSE"
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n", d, tf(c.Subdomains), c.Path, tf(c.Secure), c.Expires, c.Name, c.Value)
	}
	return atomicWrite(p, []byte(b.String()))
}
func cookieMatches(c StoredCookie, u *url.URL) bool {
	d := strings.TrimPrefix(c.Domain, ".")
	h := u.Hostname()
	domain := h == d || (c.Subdomains && strings.HasSuffix(h, "."+d))
	p := u.Path
	if p == "" {
		p = "/"
	}
	pathOK := p == c.Path || (strings.HasPrefix(p, c.Path) && (strings.HasSuffix(c.Path, "/") || strings.HasPrefix(strings.TrimPrefix(p, c.Path), "/")))
	return domain && pathOK && (!c.Secure || u.Scheme == "https") && (c.Expires == 0 || c.Expires > time.Now().Unix())
}
func cookieHeader(cs []StoredCookie, u *url.URL) string {
	cs = append([]StoredCookie(nil), cs...)
	sort.SliceStable(cs, func(i, j int) bool { return len(cs[i].Path) > len(cs[j].Path) })
	var out []string
	for _, c := range cs {
		if cookieMatches(c, u) {
			out = append(out, c.Name+"="+c.Value)
		}
	}
	return strings.Join(out, "; ")
}
func mergeCookies(cs []StoredCookie, updates []*http.Cookie, u *url.URL) []StoredCookie {
	cs = append([]StoredCookie(nil), cs...)
	for _, c := range updates {
		d := strings.ToLower(strings.TrimPrefix(c.Domain, "."))
		sub := c.Domain != ""
		if d == "" {
			d = u.Hostname()
		}
		if u.Hostname() != d && !strings.HasSuffix(u.Hostname(), "."+d) {
			continue
		}
		p := c.Path
		if p == "" {
			p = u.Path[:strings.LastIndex(u.Path, "/")+1]
			if len(p) > 1 {
				p = strings.TrimSuffix(p, "/")
			}
		}
		if p == "" {
			p = "/"
		}
		var exp int64
		if !c.Expires.IsZero() {
			exp = c.Expires.Unix()
		}
		if c.MaxAge > 0 {
			exp = time.Now().Unix() + int64(c.MaxAge)
		}
		filtered := cs[:0]
		for _, old := range cs {
			if !(strings.TrimPrefix(old.Domain, ".") == d && old.Path == p && old.Name == c.Name) {
				filtered = append(filtered, old)
			}
		}
		cs = filtered
		if c.MaxAge < 0 || (exp > 0 && exp <= time.Now().Unix()) {
			continue
		}
		if sub {
			d = "." + d
		}
		cs = append(cs, StoredCookie{d, p, c.Name, c.Value, c.Secure, c.HttpOnly, sub, exp})
	}
	return cs
}

type wireStore struct {
	Name  string `json:"storeName"`
	Parts map[string]struct {
		Display string `json:"pickupDisplay"`
	} `json:"partsAvailability"`
}

func parseStock(data []byte, c Config) (Stock, error) {
	var payload struct {
		Body struct {
			Stores  []wireStore `json:"stores"`
			Content struct {
				Pickup struct {
					Stores []wireStore `json:"stores"`
				} `json:"pickupMessage"`
			} `json:"content"`
		} `json:"body"`
	}
	if json.Unmarshal(data, &payload) != nil {
		return nil, fail("Invalid stock JSON")
	}
	stores := payload.Body.Stores
	if stores == nil {
		stores = payload.Body.Content.Pickup.Stores
	}
	out := Stock{}
	for _, s := range stores {
		for _, name := range c.Stores {
			if !strings.EqualFold(strings.TrimPrefix(s.Name, "Apple "), name) {
				continue
			}
			for part := range c.Products {
				v := s.Parts[part].Display
				if v != "available" && v != "unavailable" {
					return nil, fail("Unknown stock value; availability unknown")
				}
				out[name+"|"+part] = v == "available"
			}
		}
	}
	if len(out) != len(c.Stores)*len(c.Products) || len(out) == 0 {
		return nil, fail("Missing target store or variant; availability unknown")
	}
	return out, nil
}
func stockURL(c Config) string {
	q := url.Values{"fae": {"true"}, "pl": {"true"}, "mts.0": {"regular"}, "location": {c.Postcode}}
	for i, p := range keys(c.Products) {
		q.Set(fmt.Sprintf("parts.%d", i), p)
	}
	return c.shopURL() + "/fulfillment-messages?" + q.Encode()
}
func newClient() (tlsclient.HttpClient, error) {
	return tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), tlsclient.WithClientProfile(profiles.Chrome_152), tlsclient.WithTimeoutSeconds(30), tlsclient.WithNotFollowRedirects(), tlsclient.WithDisableHttp3())
}

func proxyURL(path string) (string, error) {
	var config struct{ Server, Username, Password string }
	if readJSON(path, &config) != nil {
		return "", fail("Could not read private proxy configuration")
	}
	u, err := url.Parse(config.Server)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5") {
		return "", fail("Invalid proxy server configuration")
	}
	u.User = url.UserPassword(config.Username, config.Password)
	return u.String(), nil
}

type Monitor struct {
	Proxy       bool
	Root        string
	Config      Config
	Client      tlsclient.HttpClient
	Recovery    Recovery
	LastRenewal float64
	Warning     string
	Endpoint    string
}

func (m *Monitor) path(name string) string { return filepath.Join(m.Root, name) }
func (m *Monitor) fetch(ctx context.Context, jar, meta string) (Stock, error) {
	var session Session
	if e := readJSON(meta, &session); e != nil || session.UserAgent == "" {
		return nil, &CheckError{Message: "Missing browser session", Session: true, Retry: 600}
	}
	cs, e := readCookies(jar)
	if e != nil {
		return nil, e
	}
	endpoint := m.Endpoint
	if endpoint == "" {
		endpoint = stockURL(m.Config)
	}
	req, e := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if e != nil {
		return nil, e
	}
	req.Header = http.Header{"accept": {"*/*"}, "accept-language": {"en-GB,en;q=0.9"}, "user-agent": {session.UserAgent}, "referer": {m.Config.buyURL()}, "sec-fetch-site": {"same-origin"}, "sec-fetch-mode": {"cors"}, "sec-fetch-dest": {"empty"}, http.HeaderOrderKey: {"user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer", "accept-language", "cookie"}}
	if ch := cookieHeader(cs, req.URL); ch != "" {
		req.Header.Set("cookie", ch)
	}
	res, e := m.Client.Do(req)
	if e != nil {
		return nil, fail("Apple TLS/HTTP connection failed")
	}
	defer res.Body.Close()
	retry := retrySeconds(res.Header.Get("Retry-After"))
	if res.StatusCode != 200 {
		return nil, &CheckError{Message: fmt.Sprintf("Apple HTTP %d", res.StatusCode), Retry: retry, Server: retry > 0, Session: res.StatusCode == 401 || res.StatusCode == 403 || res.StatusCode == 541}
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, 4*1024*1024))
	if e != nil {
		return nil, fail("Incomplete stock response")
	}
	stock, e := parseStock(b, m.Config)
	if e != nil {
		return nil, e
	}
	if e = writeCookies(jar, mergeCookies(cs, res.Cookies(), req.URL)); e != nil {
		return nil, e
	}
	return stock, nil
}
func (m *Monitor) persist() error { return saveJSON(m.path(".session-recovery.json"), m.Recovery) }
func (m *Monitor) deferError(e error) error {
	var ce *CheckError
	if errors.As(e, &ce) && ce.Server {
		m.Recovery.BlockedUntil = max(m.Recovery.BlockedUntil, epoch()+ce.Retry)
		if err := m.persist(); err != nil {
			return err
		}
	}
	return e
}
func (m *Monitor) nextRenewal() float64 {
	if cs, e := readCookies(m.path(".apple-cookies.txt")); e == nil {
		for _, c := range cs {
			if c.Name == "shld_bt_ck" && c.Expires > 0 {
				return float64(c.Expires) - 900
			}
		}
	}
	var s Session
	if readJSON(m.path(".apple-session.json"), &s) == nil && s.Expiry > 0 {
		return s.Expiry - 900
	}
	return m.LastRenewal + 3600
}
func (m *Monitor) renewBrowser(ctx context.Context) (Stock, error) {
	m.Recovery.LastAttempt = epoch()
	if e := m.persist(); e != nil {
		return nil, e
	}
	candidate := m.path(".apple-cookies.go-candidate.txt")
	defer os.Remove(candidate)
	defer os.Remove(candidate + ".json")
	os.Remove(candidate)
	os.Remove(candidate + ".json")
	node := os.Getenv("APPLE_MONITOR_NODE")
	if node == "" {
		node = "node"
	}
	ctx, cancel := context.WithTimeout(ctx, 110*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, m.path("renew-session.mjs"), "--seeded", "--refresh", "--persistent", "--output", candidate)
	cmd.Dir = m.Root
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	out, e := cmd.Output()
	var diagnostic map[string]any
	for _, line := range bytes.Split(out, []byte{'\n'}) {
		var item map[string]any
		if json.Unmarshal(line, &item) == nil {
			diagnostic = map[string]any{"at": stamp()}
			for _, k := range []string{"ok", "stage", "status", "error", "browserExitCode", "verificationExpiry", "retryAfterSeconds", "browserEnvironment", "networkSummary"} {
				if v, ok := item[k]; ok {
					diagnostic[k] = v
				}
			}
		}
	}
	if diagnostic == nil {
		diagnostic = map[string]any{"at": stamp(), "ok": false, "error": "WorkerFailed"}
	}
	if err := saveJSON(m.path(".session-diagnostic.direct.json"), diagnostic); err != nil {
		return nil, err
	}
	if e != nil {
		retry, _ := diagnostic["retryAfterSeconds"].(float64)
		return nil, m.deferError(&CheckError{Message: fmt.Sprintf("Browser renewal failed (stage=%v, status=%v, error=%v)", diagnostic["stage"], diagnostic["status"], diagnostic["error"]), Session: true, Retry: max(600, retry), Server: retry > 0})
	}
	stock, e := m.fetch(ctx, candidate, candidate+".json")
	if e != nil {
		return nil, m.deferError(e)
	}
	// Commit a candidate only after real TLS-client validation. The main lock
	// excludes readers while the cookie jar and its metadata are promoted.
	if e = os.Rename(candidate, m.path(".apple-cookies.txt")); e != nil {
		return nil, e
	}
	if e = os.Rename(candidate+".json", m.path(".apple-session.json")); e != nil {
		return nil, e
	}
	m.LastRenewal = epoch()
	m.Warning = ""
	return stock, saveJSON(m.path(".session-renewal.direct.json"), map[string]any{"renewedAt": stamp(), "route": "direct"})
}
func (m *Monitor) check(ctx context.Context) (Stock, error) {
	now := epoch()
	if now < m.Recovery.BlockedUntil {
		return nil, &CheckError{Message: "Apple cooldown; no request sent", Retry: m.Recovery.BlockedUntil - now, Server: true}
	}
	if m.Config.StockEndpoint == "retail" {
		stock, err := m.fetchRetail(ctx)
		return stock, m.deferError(err)
	}
	stock, e := m.fetch(ctx, m.path(".apple-cookies.txt"), m.path(".apple-session.json"))
	if e != nil {
		e = m.deferError(e)
		var ce *CheckError
		if errors.As(e, &ce) && ce.Session && !ce.Server && now-m.Recovery.LastAttempt >= 600 {
			stock, e = m.renew(ctx)
			if e != nil {
				m.Warning = e.Error()
				return nil, &CheckError{Message: e.Error(), Session: true, Retry: max(600, m.Recovery.BlockedUntil-epoch())}
			}
			return stock, nil
		}
		if errors.As(e, &ce) && ce.Session {
			ce.Retry = max(ce.Retry, 600)
		}
		return nil, e
	}
	if now >= m.nextRenewal() && now-m.Recovery.LastAttempt >= 600 {
		fresh, err := m.renew(ctx)
		if err != nil {
			m.Warning = err.Error()
			fmt.Println(stamp(), "Session renewal postponed:", err)
		} else {
			stock = fresh
		}
	}
	return stock, nil
}
func (m *Monitor) telegram(ctx context.Context, message string) error {
	token, e := os.ReadFile(m.path(".telegram-token"))
	if e != nil {
		return e
	}
	v := url.Values{"chat_id": {strconv.FormatInt(m.Config.ChatID, 10)}, "text": {message}, "disable_web_page_preview": {"true"}}
	req, e := http.NewRequestWithContext(ctx, "POST", "https://api.telegram.org/bot"+strings.TrimSpace(string(token))+"/sendMessage", strings.NewReader(v.Encode()))
	if e != nil {
		return fail("Invalid Telegram configuration")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Dedicated client keeps Telegram connections separate from Apple.
	client, e := newClient()
	if e != nil {
		return e
	}
	defer client.CloseIdleConnections()
	res, e := client.Do(req)
	if e != nil {
		return fail("Telegram connection failed")
	}
	defer res.Body.Close()
	var result struct {
		OK bool `json:"ok"`
	}
	e = json.NewDecoder(io.LimitReader(res.Body, 1024*1024)).Decode(&result)
	if e != nil || res.StatusCode != 200 || !result.OK {
		return fail("Telegram rejected notification")
	}
	return nil
}
func applyStock(c Config, current, state Stock, notify func(string) error) error {
	for _, k := range keys(current) {
		if current[k] && !state[k] {
			parts := strings.SplitN(k, "|", 2)
			if e := notify("Pickup available: " + c.Products[parts[1]] + "\nApple " + parts[0] + "\n" + c.buyURL() + "\nAvailability can change before checkout."); e != nil {
				return e
			}
		}
		state[k] = current[k]
	}
	return nil
}

// Service outages should be retried gently without growing to hour-long gaps.
// Explicit server cooldowns always take precedence.
func failureDelay(interval, failures int, err error) float64 {
	delay := min(3600, float64(max(60, interval))*float64(int64(1)<<min(failures, 6)))
	var ce *CheckError
	if errors.As(err, &ce) {
		if ce.Status == 503 {
			delay = float64(max(60, interval))
		}
		delay = max(delay, ce.Retry)
	}
	return delay
}
func (m *Monitor) run(ctx context.Context, once, forceRenew bool) error {
	state := Stock{}
	if e := readJSON(m.path("state.json"), &state); e != nil && !os.IsNotExist(e) {
		return e
	}
	var old struct {
		LastSuccess string `json:"lastSuccess"`
		Alerted     bool   `json:"outageAlerted"`
		Failures    int    `json:"consecutiveFailures"`
	}
	_ = readJSON(m.path("status.json"), &old)
	lastSuccess := old.LastSuccess
	failures := 0
	alerted := old.Alerted || old.Failures >= 3
	for {
		var current Stock
		var e error
		if forceRenew && epoch() < m.Recovery.BlockedUntil {
			e = &CheckError{Message: "Apple cooldown; renewal deferred", Retry: m.Recovery.BlockedUntil - epoch(), Server: true}
		} else if forceRenew {
			current, e = m.renew(ctx)
		} else {
			current, e = m.check(ctx)
		}
		forceRenew = false
		now := stamp()
		delay := float64(max(5, m.Config.Interval))
		status := map[string]any{"pid": os.Getpid(), "lastCheck": now, "lastSuccess": lastSuccess, "continuous": !once, "implementation": "go", "renewalMode": m.Config.RenewalMode, "tlsProfile": profileName, "intervalSeconds": max(5, m.Config.Interval), "stockEndpoint": m.Config.StockEndpoint, "proxy": m.Proxy, "automaticRenewal": m.Config.StockEndpoint != "retail", "nextRenewal": m.nextRenewal(), "cooldownUntil": m.Recovery.BlockedUntil, "lastRenewal": m.LastRenewal, "renewalWarning": m.Warning}
		if e == nil {
			lastSuccess = now
			status["lastSuccess"] = now
			e = applyStock(m.Config, current, state, func(s string) error { return m.telegram(ctx, s) })
			if e == nil {
				e = saveJSON(m.path("state.json"), state)
			}
		}
		if e == nil {
			if alerted {
				if err := m.telegram(ctx, m.Config.name()+": live checks have recovered."); err == nil {
					alerted = false
				}
			}
			failures = 0
			status["status"] = "healthy"
			status["stock"] = current
			b, _ := json.Marshal(current)
			fmt.Println(now, string(b))
		} else {
			failures++
			status["status"] = "error"
			status["error"] = e.Error()
			status["consecutiveFailures"] = failures
			var ce *CheckError
			if errors.As(e, &ce) {
				if ce.Session {
					status["status"] = "session-rejected"
				}
				delay = max(delay, ce.Retry)
			}
			delay = max(delay, failureDelay(m.Config.Interval, failures, e))
			if ce != nil && ce.Status == 503 {
				status["status"] = "service-unavailable"
			}
			fmt.Println(now, "CHECK FAILED — availability unknown:", e)
			if !once && !alerted && (failures >= 3 || (ce != nil && ce.Session)) {
				if err := m.telegram(ctx, m.Config.name()+": checks or session renewal are failing. Availability is unknown. Retrying automatically with backoff."); err == nil {
					alerted = true
				}
			}
		}
		status["outageAlerted"] = alerted
		status["nextCheck"] = time.Now().UTC().Add(time.Duration(delay * float64(time.Second))).Format(time.RFC3339)
		status["retrySeconds"] = delay
		if err := saveJSON(m.path("status.json"), status); err != nil {
			return err
		}
		if once {
			return e
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Duration(delay * float64(time.Second))):
		}
	}
}
func main() {
	if e := entry(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func entry() error {
	root := flag.String("root", ".", "Monitor directory")
	once := flag.Bool("once", false, "One check and exit")
	renew := flag.Bool("renew", false, "Renew browser session before check")
	retailProbe := flag.Bool("retail-probe", false, "Probe the alternate retail endpoint without cookies")
	samples := flag.Int("samples", 1, "Number of retail probe samples, maximum 12")
	spacing := flag.Int("spacing", 10, "Seconds between retail probes, minimum 5")
	httpRenew := flag.Bool("probe-http-renewal", false, "Test HTTP-only verification in a private candidate session")
	cold := flag.Bool("cold", false, "Use no existing cookies for HTTP renewal probe")
	testTelegram := flag.Bool("test-telegram", false, "Send a labelled notification test")
	probe := flag.Bool("probe", false, "Read-only live stock probe; no alerts or session changes")
	proxyFile := flag.String("proxy-file", "", "Private proxy configuration for diagnostic probes")
	cookieFile := flag.String("cookie-file", "", "Alternate cookie jar for a read-only probe")
	sessionFile := flag.String("session-file", "", "Alternate browser metadata for a read-only probe")
	tlsCheck := flag.Bool("tls-check", false, "Independent TLS handshake diagnostic; no Apple cookies sent")
	flag.Parse()
	abs, e := filepath.Abs(*root)
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	client, e := newClient()
	if e != nil {
		return e
	}
	defer client.CloseIdleConnections()
	if *proxyFile != "" {
		if !*probe && !*tlsCheck && !*httpRenew && !*retailProbe {
			return fail("Proxy mode is currently limited to diagnostics; live renewal uses the direct route")
		}
		proxy, err := proxyURL(*proxyFile)
		if err != nil {
			return err
		}
		if client.SetProxy(proxy) != nil {
			return fail("Could not configure proxy transport")
		}
	}
	if *tlsCheck {
		req, _ := http.NewRequestWithContext(ctx, "GET", "https://tls.peet.ws/api/all", nil)
		res, e := client.Do(req)
		if e != nil {
			return fail("TLS diagnostic connection failed")
		}
		defer res.Body.Close()
		var data map[string]any
		if e = json.NewDecoder(io.LimitReader(res.Body, 1024*1024)).Decode(&data); e != nil {
			return e
		}
		tls, _ := data["tls"].(map[string]any)
		return printJSON(map[string]any{"profile": profileName, "httpVersion": data["http_version"], "tlsVersion": tls["tls_version_negotiated"], "ja3": tls["ja3"], "ja4": tls["ja4"]})
	}
	if *retailProbe {
		m := &Monitor{Root: abs, Client: client, Proxy: *proxyFile != ""}
		if e = readJSON(m.path("config.json"), &m.Config); e != nil {
			return e
		}
		if e = readJSON(m.path(".session-recovery.json"), &m.Recovery); e != nil && !os.IsNotExist(e) {
			return e
		}
		if epoch() < m.Recovery.BlockedUntil {
			return fail("Apple cooldown active")
		}
		for i := 0; i < max(1, min(*samples, 12)); i++ {
			if i > 0 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(time.Duration(max(*spacing, 5)) * time.Second):
				}
			}
			start := time.Now()
			stock, err := m.fetchRetail(ctx)
			if err != nil {
				return err
			}
			if e = printJSON(map[string]any{"at": stamp(), "sample": i + 1, "milliseconds": time.Since(start).Milliseconds(), "stock": stock, "proxy": *proxyFile != ""}); e != nil {
				return e
			}
		}
		return nil
	}
	if *httpRenew {
		m := &Monitor{Root: abs, Client: client}
		if e = readJSON(m.path("config.json"), &m.Config); e != nil {
			return e
		}
		if e = readJSON(m.path(".session-recovery.json"), &m.Recovery); e != nil && !os.IsNotExist(e) {
			return e
		}
		return m.probeHTTP(ctx, *cold)
	}
	if *testTelegram {
		m := &Monitor{Root: abs, Client: client}
		if e = readJSON(m.path("config.json"), &m.Config); e != nil {
			return e
		}
		return m.telegram(ctx, "Go monitor notification test: Telegram delivery is working. This is not a stock alert.")
	}
	if *probe {
		m := &Monitor{Root: abs, Client: client}
		if e = readJSON(m.path("config.json"), &m.Config); e != nil {
			return e
		}
		var recovery Recovery
		if e = readJSON(m.path(".session-recovery.json"), &recovery); e != nil && !os.IsNotExist(e) {
			return e
		}
		if epoch() < recovery.BlockedUntil {
			return fail("Apple cooldown is active; probe not sent")
		}
		temp, e := os.MkdirTemp("", "iphone-probe-")
		if e != nil {
			return e
		}
		defer os.RemoveAll(temp)
		jar := filepath.Join(temp, "cookies.txt")
		sourceJar := m.path(".apple-cookies.txt")
		if *cookieFile != "" {
			sourceJar = *cookieFile
		}
		metadata := m.path(".apple-session.json")
		if *sessionFile != "" {
			metadata = *sessionFile
		}
		b, e := os.ReadFile(sourceJar)
		if e != nil {
			return e
		}
		if e = atomicWrite(jar, b); e != nil {
			return e
		}
		stock, e := m.fetch(ctx, jar, metadata)
		if e != nil {
			return e
		}
		return printJSON(map[string]any{"stock": stock, "tlsProfile": profileName, "at": stamp()})
	}
	lock, e := os.OpenFile(filepath.Join(abs, ".monitor.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return fail("Another monitor is running")
	}
	m := &Monitor{Root: abs, Client: client}
	if e = readJSON(m.path("config.json"), &m.Config); e != nil {
		return e
	}
	if m.Config.RetailProxyFile != "" {
		if m.Config.StockEndpoint != "retail" || *renew {
			return fail("Live proxies require the anonymous retail endpoint without forced renewal")
		}
		path := m.Config.RetailProxyFile
		if !filepath.IsAbs(path) {
			path = m.path(path)
		}
		proxy, err := proxyURL(path)
		if err != nil {
			return err
		}
		if client.SetProxy(proxy) != nil {
			return fail("Could not configure retail proxy")
		}
		m.Proxy = true
	}
	if m.Config.ChatID == 0 || len(m.Config.Products) == 0 || len(m.Config.Stores) == 0 {
		return fail("Invalid monitor config")
	}
	if e = readJSON(m.path(".session-recovery.json"), &m.Recovery); e != nil && !os.IsNotExist(e) {
		return e
	}
	var saved struct {
		RenewedAt string `json:"renewedAt"`
	}
	if readJSON(m.path(".session-renewal.direct.json"), &saved) == nil {
		if t, e := time.Parse(time.RFC3339Nano, saved.RenewedAt); e == nil {
			m.LastRenewal = float64(t.Unix())
		}
	}
	return m.run(ctx, *once, *renew)
}
func printJSON(v any) error { return json.NewEncoder(os.Stdout).Encode(v) }
