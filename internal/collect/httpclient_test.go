package collect

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

func newTestCache() *dnsCache {
	return &dnsCache{
		resolver: net.DefaultResolver,
		dialer:   &net.Dialer{Timeout: 5 * time.Second},
		ttl:      time.Minute,
		entries:  make(map[string]dnsEntry),
	}
}

func TestDNSCacheIPLiteralNotResolved(t *testing.T) {
	c := newTestCache()
	ips, err := c.lookup(context.Background(), "203.0.113.7")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(ips) != 1 || ips[0] != "203.0.113.7" {
		t.Errorf("IP literal should pass through unchanged, got %v", ips)
	}
	// Nothing should have been cached for an IP literal.
	if len(c.entries) != 0 {
		t.Errorf("IP literal should not populate the cache, got %v", c.entries)
	}
}

func TestDNSCacheCachesAndServesStale(t *testing.T) {
	c := newTestCache()

	// Prime the cache directly (avoids depending on a real resolver), then confirm
	// a hit within TTL returns it without touching the resolver.
	c.entries["example.test"] = dnsEntry{ips: []string{"198.51.100.9"}, expires: time.Now().Add(time.Minute)}
	ips, err := c.lookup(context.Background(), "example.test")
	if err != nil || len(ips) != 1 || ips[0] != "198.51.100.9" {
		t.Fatalf("cache hit: got %v, err %v", ips, err)
	}

	// Expire it and point the resolver at a host that won't resolve: stale must be
	// served rather than failing.
	c.entries["example.test"] = dnsEntry{ips: []string{"198.51.100.9"}, expires: time.Now().Add(-time.Minute)}
	c.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, &net.DNSError{Err: "forced failure", Name: "example.test", IsTemporary: true}
		},
	}
	ips, err = c.lookup(context.Background(), "example.test")
	if err != nil || len(ips) != 1 || ips[0] != "198.51.100.9" {
		t.Errorf("stale-on-failure: got %v, err %v; want served stale entry", ips, err)
	}
}

func TestDNSCacheDialConnects(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if conn, err := ln.Accept(); err == nil {
			conn.Close()
		}
	}()

	c := newTestCache()
	conn, err := c.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("DialContext to %s: %v", ln.Addr(), err)
	}
	conn.Close()
}

// The shared client must be a plain *http.Client (not the SDK BuildableClient), so
// service NewFromConfig uses it as-is and every client shares its one transport.
func TestSharedHTTPClientIsPlainAndShared(t *testing.T) {
	if sharedHTTPClient == nil || sharedHTTPClient.Transport == nil {
		t.Fatal("sharedHTTPClient not initialized")
	}
	if _, ok := sharedHTTPClient.Transport.(*http.Transport); !ok {
		t.Errorf("transport is %T, want *http.Transport", sharedHTTPClient.Transport)
	}
	if newSharedHTTPClient() == nil {
		t.Error("newSharedHTTPClient returned nil")
	}
}
