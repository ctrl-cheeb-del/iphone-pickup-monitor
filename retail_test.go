package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRetailCheckAndCooldown(t *testing.T) {
	c, _ := fixture()
	c.StockEndpoint = "retail"
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Cookie") != "" {
			t.Error("unexpected cookies")
		}
		if calls == 1 {
			w.Write([]byte(`{"body":{"stores":[{"storeName":"Manchester Arndale","partsAvailability":{"p1":{"pickupDisplay":"available"}}}]}}`))
			return
		}
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(429)
	}))
	defer srv.Close()
	client, err := newClient()
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	m := Monitor{Root: t.TempDir(), Config: c, Client: client, Endpoint: srv.URL}
	stock, err := m.check(context.Background())
	if err != nil || !stock["Manchester Arndale|p1"] {
		t.Fatal(stock, err)
	}
	_, err = m.check(context.Background())
	var ce *CheckError
	if !errors.As(err, &ce) || !ce.Server {
		t.Fatal(err)
	}
	_, err = m.check(context.Background())
	if err == nil || calls != 2 {
		t.Fatal("cooldown sent request", calls, err)
	}
}
func TestStorefrontURLs(t *testing.T) {
	c, _ := fixture()
	if got := c.buyURL(); got != "https://www.apple.com/uk/shop/buy-iphone/iphone-duo" {
		t.Fatal(got)
	}
	c.Country = "de"
	if got := c.shopURL() + "/retail/pickup-message"; got != "https://www.apple.com/de/shop/retail/pickup-message" {
		t.Fatal(got)
	}
	if got := stockURL(c); !strings.HasPrefix(got, "https://www.apple.com/de/shop/fulfillment-messages?") {
		t.Fatal(got)
	}
	if got := c.productPage(); got != "https://www.apple.com/de/shop/buy-iphone/iphone-duo" {
		t.Fatal(got)
	}
	c.ProductPage = "https://www.apple.com/de/shop/buy-iphone/iphone-duo/x"
	if got := c.productPage(); got != c.ProductPage {
		t.Fatal(got)
	}
}
func TestRetailRejectsUnknownStock(t *testing.T) {
	c, _ := fixture()
	for _, body := range []string{`{"body":{"stores":[]}}`, `{"body":{"stores":[{"storeName":"Manchester Arndale","partsAvailability":{"p1":{"pickupDisplay":"unknown"}}}]}}`} {
		if _, err := parseStock([]byte(body), c); err == nil {
			t.Fatal("accepted unknown stock")
		}
	}
}

func TestFailureDelay(t *testing.T) {
	for _, tt := range []struct {
		code     int
		retry    float64
		failures int
		want     float64
	}{
		{503, 0, 1, 60}, {503, 0, 12, 60}, {503, 900, 12, 900}, {429, 0, 3, 480}, {429, 7200, 12, 7200}, {541, 0, 12, 3600},
	} {
		got := failureDelay(5, tt.failures, &CheckError{Status: tt.code, Retry: tt.retry})
		if got != tt.want {
			t.Errorf("status %d: got %v want %v", tt.code, got, tt.want)
		}
	}
}
