// Package clientip finds the address of the client behind a request, which
// per-address limits count by.
//
// Behind a reverse proxy every request comes from the proxy, which names the
// client in a header such as X-Forwarded-For. The header is believed only
// from trusted proxies: anyone else could write any address into it.
package clientip

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Resolver finds client addresses. Its zero value uses the connection's
// address.
type Resolver struct {
	trusted []netip.Prefix
	header  string
}

// New returns a resolver that believes header from the proxies in trusted.
// header is X-Forwarded-For, or a header with one address like
// CF-Connecting-IP or X-Real-IP.
func New(trusted []netip.Prefix, header string) *Resolver {
	return &Resolver{trusted: trusted, header: http.CanonicalHeaderKey(header)}
}

// ParsePrefixes reads a comma-separated list of networks and addresses, such
// as "10.0.0.0/8, 127.0.0.1".
func ParsePrefixes(list string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(item); err == nil {
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("%q is neither a network nor an address", item)
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
	}
	return prefixes, nil
}

func (r *Resolver) isTrusted(addr netip.Addr) bool {
	for _, prefix := range r.trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// Addr returns the client address of req, or the zero Addr if it has none.
func (r *Resolver) Addr(req *http.Request) netip.Addr {
	remote := parse(req.RemoteAddr)
	if r == nil || r.header == "" || !remote.IsValid() || !r.isTrusted(remote) {
		return remote
	}
	// Proxies append the address they got the request from, so the client
	// is the last address that is not a trusted proxy.
	var hops []string
	for _, value := range req.Header.Values(r.header) {
		hops = append(hops, strings.Split(value, ",")...)
	}
	client := remote
	for i := len(hops) - 1; i >= 0; i-- {
		addr := parse(strings.TrimSpace(hops[i]))
		if !addr.IsValid() {
			break
		}
		client = addr
		if !r.isTrusted(addr) {
			break
		}
	}
	return client
}

// parse reads an address with or without a port.
func parse(s string) netip.Addr {
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	addr, err := netip.ParseAddr(strings.Trim(s, "[]"))
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap().WithZone("")
}

// Key returns what limits count an address as: the address itself for IPv4,
// its /64 network for IPv6, since one subscriber usually has a whole /64.
func Key(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	if addr.Is6() {
		prefix, _ := addr.Prefix(64)
		return prefix.String()
	}
	return addr.String()
}

type contextKey struct{}

// Middleware stores the client address of each request for FromContext.
func (r *Resolver) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := context.WithValue(req.Context(), contextKey{}, r.Addr(req))
		next.ServeHTTP(w, req.WithContext(ctx))
	})
}

// FromContext returns the client address Middleware stored.
func FromContext(ctx context.Context) netip.Addr {
	addr, _ := ctx.Value(contextKey{}).(netip.Addr)
	return addr
}
