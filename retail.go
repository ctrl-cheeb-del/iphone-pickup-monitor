package main

import (
	"context"
	"fmt"
	http "github.com/bogdanfinn/fhttp"
	"io"
	"net/url"
)

func (m *Monitor) fetchRetail(ctx context.Context) (Stock, error) {
	q := url.Values{"pl": {"true"}, "location": {m.Config.Postcode}}
	for i, p := range keys(m.Config.Products) {
		q.Set(fmt.Sprintf("parts.%d", i), p)
	}
	endpoint := m.Config.shopURL() + "/retail/pickup-message?" + q.Encode()
	if m.Endpoint != "" {
		endpoint = m.Endpoint
	}
	req, e := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if e != nil {
		return nil, e
	}
	req.Header = http.Header{"accept": {"application/json"}, "user-agent": {"Mozilla/5.0"}, "referer": {m.Config.shopURL() + "/buy-iphone/"}, http.HeaderOrderKey: {"user-agent", "accept", "referer"}}
	// A new CONNECT tunnel lets the rotating gateway select a fresh exit.
	if m.Proxy {
		m.Client.CloseIdleConnections()
	}
	res, e := m.Client.Do(req)
	if e != nil {
		return nil, fail("Retail endpoint connection failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		r := retrySeconds(res.Header.Get("Retry-After"))
		return nil, &CheckError{Message: fmt.Sprintf("Retail endpoint HTTP %d", res.StatusCode), Status: res.StatusCode, Retry: r, Server: r > 0}
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, 4*1024*1024))
	if e != nil {
		return nil, e
	}
	return parseStock(b, m.Config)
}
