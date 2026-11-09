package clientip

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestAddr(t *testing.T) {
	trusted, err := ParsePrefixes("10.0.0.0/8, 127.0.0.1, ::1")
	if err != nil {
		t.Fatal(err)
	}
	xff := New(trusted, "X-Forwarded-For")
	cf := New(trusted, "CF-Connecting-IP")

	tests := []struct {
		name     string
		resolver *Resolver
		remote   string
		headers  []string
		want     string
	}{
		{"no proxy", nil, "203.0.113.7:4000", []string{"1.2.3.4"}, "203.0.113.7"},
		{"untrusted sender", xff, "203.0.113.7:4000", []string{"1.2.3.4"}, "203.0.113.7"},
		{"trusted proxy", xff, "10.1.2.3:4000", []string{"198.51.100.1"}, "198.51.100.1"},
		{"spoofed first hop", xff, "10.1.2.3:4000", []string{"1.1.1.1, 198.51.100.1"}, "198.51.100.1"},
		{"proxy chain", xff, "127.0.0.1:4000", []string{"198.51.100.1, 10.9.9.9"}, "198.51.100.1"},
		{"repeated header", xff, "127.0.0.1:4000", []string{"198.51.100.1", "10.9.9.9"}, "198.51.100.1"},
		{"garbage", xff, "10.1.2.3:4000", []string{"not an address"}, "10.1.2.3"},
		{"no header", xff, "10.1.2.3:4000", nil, "10.1.2.3"},
		{"single address header", cf, "[::1]:4000", []string{"2001:db8::1"}, "2001:db8::1"},
		{"mapped address", nil, "[::ffff:198.51.100.1]:80", nil, "198.51.100.1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = test.remote
			for _, value := range test.headers {
				req.Header.Add("X-Forwarded-For", value)
				req.Header.Add("CF-Connecting-IP", value)
			}
			if got := test.resolver.Addr(req); got.String() != test.want {
				t.Fatalf("Addr = %v, want %v", got, test.want)
			}
		})
	}
}

func TestKey(t *testing.T) {
	for addr, want := range map[string]string{
		"198.51.100.1":         "198.51.100.1",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
	} {
		if got := Key(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Key(%s) = %s, want %s", addr, got, want)
		}
	}
	if Key(netip.Addr{}) != "" {
		t.Error("an unknown address has a key")
	}
	if _, err := ParsePrefixes("10.0.0.0/8, nonsense"); err == nil {
		t.Error("ParsePrefixes accepted nonsense")
	}
}
