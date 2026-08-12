package collect

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// sharedHTTPClient is one *http.Client — hence one *http.Transport and one
// connection pool — reused by every AWS service client across every account,
// service, and region. It is deliberately a plain *http.Client rather than the
// SDK's *awshttp.BuildableClient: a service's NewFromConfig clones a BuildableClient
// into a fresh transport (empty pool) per client, whereas a non-BuildableClient is
// used as-is. Since awshound builds a client per region (fanRegions), that clone
// would give us hundreds of independent pools — no keep-alive reuse and a DNS
// lookup per client — which floods a resolver. Sharing one client instead reuses
// connections and, via the DNS cache below, resolves each host at most once per
// TTL. It is passed to every session with config.WithHTTPClient.
var sharedHTTPClient = newSharedHTTPClient()

func newSharedHTTPClient() *http.Client {
	cache := &dnsCache{
		resolver: net.DefaultResolver,
		dialer:   &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second},
		ttl:      5 * time.Minute,
		entries:  make(map[string]dnsEntry),
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           cache.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          200,
			MaxIdleConnsPerHost:   100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
}

// dnsCache resolves each host at most once per ttl and dials the cached address,
// collapsing the fan-out's DNS load to roughly one lookup per unique endpoint. It
// is safe for concurrent use. Dialing by IP keeps TLS intact: http.Transport sets
// the TLS ServerName from the request URL host (the hostname it passed to
// DialContext), not from the address we actually dial, so SNI and certificate
// verification still use the real hostname.
type dnsCache struct {
	resolver *net.Resolver
	dialer   *net.Dialer
	ttl      time.Duration

	mu      sync.Mutex
	entries map[string]dnsEntry
}

type dnsEntry struct {
	ips     []string
	expires time.Time
}

// DialContext resolves the host portion of addr through the cache and dials the
// resulting address(es), trying each until one connects.
func (c *dnsCache) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := c.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		conn, derr := c.dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("dnscache: no addresses resolved for %q", host)
	}
	return nil, lastErr
}

// lookup returns the cached addresses for host, resolving (and caching) on a miss
// or expiry. An IP literal is returned verbatim. If a fresh resolution fails but a
// previous (now-expired) entry exists, the stale entry is served — under a flaky
// resolver a slightly stale AWS endpoint IP beats a hard failure for the short
// life of a collection run.
func (c *dnsCache) lookup(ctx context.Context, host string) ([]string, error) {
	if net.ParseIP(host) != nil {
		return []string{host}, nil
	}
	now := time.Now()

	c.mu.Lock()
	entry, ok := c.entries[host]
	c.mu.Unlock()
	if ok && now.Before(entry.expires) {
		return entry.ips, nil
	}

	ips, err := c.resolver.LookupHost(ctx, host)
	if err != nil {
		if ok && len(entry.ips) > 0 {
			return entry.ips, nil // serve stale rather than fail
		}
		return nil, err
	}

	c.mu.Lock()
	c.entries[host] = dnsEntry{ips: ips, expires: now.Add(c.ttl)}
	c.mu.Unlock()
	return ips, nil
}
