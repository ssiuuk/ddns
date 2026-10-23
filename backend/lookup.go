package backend

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/ssiuhk/ddns/shared"
)

// zoneTTL is the TTL of the SOA and NS records, which rarely change. The
// TTL of host records is a setting, see shared.DefaultRecordTTL.
const zoneTTL = 3600

// negativeTTL is how long resolvers remember that a host does not exist, the
// SOA minimum. It is short, so a new host resolves right away.
const negativeTTL = 5

// ttlRefresh is how often the host record TTL is read from the store.
const ttlRefresh = 5 * time.Second

// zoneID is the domain id we report to PowerDNS for the single zone we serve.
const zoneID = 1

type Request struct {
	QType      string
	QName      string
	Remote     string
	Local      string
	RealRemote string
	ZoneId     int
}

type Response struct {
	QType    string `json:"qtype"`
	QName    string `json:"qname"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	DomainID int    `json:"domain_id"`
	Auth     bool   `json:"auth"`
}

type HostLookup struct {
	config *shared.Config
	hosts  shared.HostBackend

	mu      sync.Mutex
	ttl     int
	ttlRead time.Time
}

func NewHostLookup(config *shared.Config, hostsBackend shared.HostBackend) *HostLookup {
	return &HostLookup{config: config, hosts: hostsBackend}
}

// Lookup returns every record matching the request. PowerDNS mostly asks for
// ANY and filters itself, so ANY returns the full RRset of the name.
func (l *HostLookup) Lookup(request *Request) ([]*Response, error) {
	queryName := shared.NormalizeName(request.QName)

	var records []*Response

	if queryName == l.config.Zone() {
		records = []*Response{
			l.record(request.QName, "SOA", fmt.Sprintf("%s. hostmaster.%s. %d 1800 3600 7200 %d",
				l.config.SOAFqdn, l.config.Zone(), l.currentSOASerial(), negativeTTL), zoneTTL),
		}
		for _, ns := range l.nameservers() {
			records = append(records, l.record(request.QName, "NS", ns, zoneTTL))
		}
	} else {
		hostname, err := l.extractHostname(queryName)
		if err != nil {
			return nil, err
		}

		host, err := l.hosts.GetHost(hostname)
		if err != nil {
			return nil, err
		}

		ttl := l.recordTTL()
		if host.IPv4 != "" {
			records = append(records, l.record(request.QName, "A", host.IPv4, ttl))
		}
		if host.IPv6 != "" {
			records = append(records, l.record(request.QName, "AAAA", host.IPv6, ttl))
		}
	}

	if request.QType == "ANY" {
		return records, nil
	}

	var matching []*Response
	for _, record := range records {
		if record.QType == request.QType {
			matching = append(matching, record)
		}
	}

	if len(matching) == 0 {
		return nil, errors.New("No record of the requested type")
	}

	return matching, nil
}

func (l *HostLookup) record(qname, qtype, content string, ttl int) *Response {
	return &Response{QType: qtype, QName: qname, Content: content, TTL: ttl, DomainID: zoneID, Auth: true}
}

// recordTTL returns the TTL of host records the admin set, read at most every
// ttlRefresh. When it can not be read, the last one read stays in use.
func (l *HostLookup) recordTTL() int {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.ttl == 0 {
		l.ttl = shared.DefaultRecordTTL
	}
	store, ok := l.hosts.(shared.RecordTTLStore)
	if !ok || time.Since(l.ttlRead) < ttlRefresh {
		return l.ttl
	}
	l.ttlRead = time.Now()
	ttl, err := store.RecordTTL()
	if err != nil {
		log.Printf("Could not read the record TTL, using %d seconds: %v", l.ttl, err)
		return l.ttl
	}
	l.ttl = ttl
	return ttl
}

func (l *HostLookup) nameservers() []string {
	if len(l.config.Nameservers) > 0 {
		return l.config.Nameservers
	}
	return []string{l.config.SOAFqdn}
}

// extractHostname extract the host part of the fqdn: pi.d.example.org -> pi
func (l *HostLookup) extractHostname(queryName string) (string, error) {
	hostname := ""
	if strings.HasSuffix(queryName, l.config.Domain) {
		hostname = queryName[:len(queryName)-len(l.config.Domain)]
	}

	if hostname == "" || strings.Contains(hostname, ".") {
		return "", errors.New("Query name does not correspond to our domain")
	}

	return hostname, nil
}

// currentSOASerial get the current SOA serial by returning the current time in seconds
func (l *HostLookup) currentSOASerial() int64 {
	return time.Now().Unix()
}
