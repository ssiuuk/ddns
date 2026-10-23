package backend

import (
	"errors"
	"github.com/ssiuhk/ddns/shared"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

type testHostBackend struct {
	hosts map[string]*shared.Host
	ttl   int
}

func (b *testHostBackend) RecordTTL() (int, error) {
	if b.ttl == 0 {
		return shared.DefaultRecordTTL, nil
	}
	return b.ttl, nil
}
func (b *testHostBackend) SetRecordTTL(ttl int) error { b.ttl = ttl; return nil }

func (b *testHostBackend) GetHost(hostname string) (*shared.Host, error) {
	host, ok := b.hosts[hostname]
	if ok {
		return host, nil
	} else {
		return nil, errors.New("Host not found")
	}
}

func (b *testHostBackend) SetHost(host *shared.Host) error {
	b.hosts[host.Hostname] = host
	return nil
}

func (b *testHostBackend) CreateHost(host *shared.Host) error {
	if _, ok := b.hosts[host.Hostname]; ok {
		return shared.ErrHostExists
	}
	return b.SetHost(host)
}

func (b *testHostBackend) UpdateHost(name string, update func(*shared.Host) error) (*shared.Host, error) {
	host, err := b.GetHost(name)
	if err != nil {
		return nil, err
	}
	return host, update(host)
}

func buildLookup(domain string) (*shared.Config, *testHostBackend, *HostLookup) {
	config := &shared.Config{
		Verbose: false,
		Domain:  domain,
		SOAFqdn: "dns" + domain,
	}

	hosts := &testHostBackend{
		hosts: map[string]*shared.Host{
			"www": {
				Hostname: "www",
				IPv4:     "10.11.12.13",
				Token:    "abcdef",
			},
			"v4": {
				Hostname: "v4",
				IPv4:     "10.10.10.10",
				Token:    "ghijkl",
			},
			"dual": {
				Hostname: "dual",
				IPv4:     "10.20.30.40",
				IPv6:     "2001:db8::40",
				Token:    "mnopqr",
			},
			"v6": {
				Hostname: "v6",
				IPv6:     "2001:db8:85a3::8a2e:370:7334",
				Token:    "ghijkl",
			},
		},
	}

	return config, hosts, NewHostLookup(config, hosts)
}

func buildRequest(queryName, queryType string) *Request {
	return &Request{
		QType: queryType,
		QName: queryName,
	}
}

func assertSingle(t *testing.T, records []*Response, err error, qtype, qname, content string) {
	t.Helper()
	assert.Nil(t, err)
	if assert.Len(t, records, 1) {
		assert.Equal(t, qtype, records[0].QType)
		assert.Equal(t, qname, records[0].QName)
		assert.Equal(t, content, records[0].Content)
		want := 5
		if qtype == "NS" || qtype == "SOA" {
			want = 3600
		}
		assert.Equal(t, want, records[0].TTL)
	}
}

func assertNone(t *testing.T, records []*Response, err error) {
	t.Helper()
	assert.NotNil(t, err)
	assert.Empty(t, records)
}

func TestRequestHandling(t *testing.T) {
	_, _, lookup := buildLookup(".example.org")

	records, err := lookup.Lookup(buildRequest("example.org.", "SOA"))
	assert.Nil(t, err)
	if assert.Len(t, records, 1) {
		assert.Equal(t, "SOA", records[0].QType)
		assert.Equal(t, "example.org.", records[0].QName)
		assert.Regexp(t, "dns\\.example\\.org\\. hostmaster\\.example.org\\. \\d+ 1800 3600 7200 5", records[0].Content)
	}

	records, err = lookup.Lookup(buildRequest("example.org.", "NS"))
	assertSingle(t, records, err, "NS", "example.org.", "dns.example.org")

	// the apex has both SOA and NS
	records, err = lookup.Lookup(buildRequest("example.org.", "ANY"))
	assert.Nil(t, err)
	assert.Len(t, records, 2)

	// every configured nameserver is announced
	config, _, multi := buildLookup(".example.org")
	config.Nameservers = []string{"ns1.example.net", "ns2.example.net"}
	records, err = multi.Lookup(buildRequest("example.org.", "NS"))
	assert.Nil(t, err)
	if assert.Len(t, records, 2) {
		assert.Equal(t, "ns1.example.net", records[0].Content)
		assert.Equal(t, "ns2.example.net", records[1].Content)
	}

	// SOA and NS only exist at the apex, otherwise hosts would look like zones or delegations
	records, err = lookup.Lookup(buildRequest("www.example.org.", "SOA"))
	assertNone(t, records, err)
	records, err = lookup.Lookup(buildRequest("www.example.org.", "NS"))
	assertNone(t, records, err)

	records, err = lookup.Lookup(buildRequest("www.example.org.", "ANY"))
	assertSingle(t, records, err, "A", "www.example.org.", "10.11.12.13")

	records, err = lookup.Lookup(buildRequest("www.example.org", "A"))
	assertSingle(t, records, err, "A", "www.example.org", "10.11.12.13")

	// Allow hostname to be mixed case which is used by Let's Encrypt for a little bit more security
	records, err = lookup.Lookup(buildRequest("wWW.eXaMPlE.oRg.", "A"))
	assertSingle(t, records, err, "A", "wWW.eXaMPlE.oRg.", "10.11.12.13")

	records, err = lookup.Lookup(buildRequest("notexisting.example.org.", "A"))
	assertNone(t, records, err)

	records, err = lookup.Lookup(buildRequest("sub.www.example.org.", "ANY"))
	assertNone(t, records, err)

	records, err = lookup.Lookup(buildRequest("www.example.com.", "ANY"))
	assertNone(t, records, err)

	// Correct Handling of IPv4/IPv6 and ANY/A/AAAA
	records, err = lookup.Lookup(buildRequest("v4.example.org.", "ANY"))
	assertSingle(t, records, err, "A", "v4.example.org.", "10.10.10.10")

	records, err = lookup.Lookup(buildRequest("v4.example.org.", "A"))
	assertSingle(t, records, err, "A", "v4.example.org.", "10.10.10.10")

	records, err = lookup.Lookup(buildRequest("v4.example.org.", "AAAA"))
	assertNone(t, records, err)

	records, err = lookup.Lookup(buildRequest("v6.example.org.", "ANY"))
	assertSingle(t, records, err, "AAAA", "v6.example.org.", "2001:db8:85a3::8a2e:370:7334")

	records, err = lookup.Lookup(buildRequest("v6.example.org.", "AAAA"))
	assertSingle(t, records, err, "AAAA", "v6.example.org.", "2001:db8:85a3::8a2e:370:7334")

	records, err = lookup.Lookup(buildRequest("v6.example.org.", "A"))
	assertNone(t, records, err)

	// a host can have both an IPv4 and an IPv6 address
	records, err = lookup.Lookup(buildRequest("dual.example.org.", "ANY"))
	assert.Nil(t, err)
	if assert.Len(t, records, 2) {
		assert.Equal(t, "A", records[0].QType)
		assert.Equal(t, "10.20.30.40", records[0].Content)
		assert.Equal(t, "AAAA", records[1].QType)
		assert.Equal(t, "2001:db8::40", records[1].Content)
	}

	records, err = lookup.Lookup(buildRequest("dual.example.org.", "AAAA"))
	assertSingle(t, records, err, "AAAA", "dual.example.org.", "2001:db8::40")
}

func TestRecordTTLs(t *testing.T) {
	_, hosts, lookup := buildLookup(".example.org")
	hosts.ttl = 300

	records, err := lookup.Lookup(buildRequest("dual.example.org.", "ANY"))
	assert.Nil(t, err)
	if assert.Len(t, records, 2) {
		assert.Equal(t, 300, records[0].TTL)
		assert.Equal(t, 300, records[1].TTL)
	}

	// the zone records keep their own TTL, and the SOA minimum, which
	// resolvers cache missing hosts for, stays short
	records, err = lookup.Lookup(buildRequest("example.org.", "SOA"))
	assert.Nil(t, err)
	if assert.Len(t, records, 1) {
		assert.Equal(t, 3600, records[0].TTL)
		assert.Regexp(t, " 5$", records[0].Content)
	}

	// a change is picked up after a few seconds, not on every query
	hosts.ttl = 60
	records, _ = lookup.Lookup(buildRequest("www.example.org.", "A"))
	assert.Equal(t, 300, records[0].TTL)
	lookup.ttlRead = time.Time{}
	records, _ = lookup.Lookup(buildRequest("www.example.org.", "A"))
	assert.Equal(t, 60, records[0].TTL)
}
