package dns

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const DefaultTimeout = 5 * time.Second

var (
	localm *dns.Msg
	localc *dns.Client
)

// Config is the DNS checker configuration settings container.
type Config struct {
	// FQDN is the DNS Name to Check from DNS Serrver.
	FQDN string

	// Domain Name to Check from DNS Server. Check if the DNS resolves the SOA for the domain
	Domain string

	// Name Server to use for Resolution
	NSServer string
	NSPort   string

	// RequestTimeout is the duration that health check will try to consume published test message.
	// If not set - 5 seconds
	RequestTimeout time.Duration
}

func localQuery(qname string, qtype uint16, nsserver string, nsport string) (*dns.Msg, error) {
	localm.SetQuestion(qname, qtype)

	r, _, err := localc.Exchange(localm, nsserver+":"+nsport)
	if err != nil {
		return nil, err
	}
	if r == nil || r.Rcode == dns.RcodeNameError || r.Rcode == dns.RcodeSuccess {
		return r, err
	}

	return nil, errors.New("no name server to answer the question")
}

// New creates new DNS health check that verifies the DNS responds and resolves the NS Records for the domain.
// Validates the DNS response to return the a specific value for an NS server
func New(config Config) func(ctx context.Context) error {
	if config.RequestTimeout == 0 {
		config.RequestTimeout = DefaultTimeout
	}

	return func(_ context.Context) error {
		var err error

		localm = &dns.Msg{
			MsgHdr: dns.MsgHdr{
				RecursionDesired: true,
			},
			Question: make([]dns.Question, 1),
		}
		localc = &dns.Client{
			ReadTimeout: config.RequestTimeout,
		}
		r, err := localQuery(dns.Fqdn(config.Domain), dns.TypeNS, config.NSServer, config.NSPort)
		if err != nil || r == nil {
			return fmt.Errorf("cannot retrieve the list of name servers for %s: %s\n", dns.Fqdn(config.Domain), err)
		}
		if r.Rcode == dns.RcodeNameError {
			return fmt.Errorf("no such domain %s\n", dns.Fqdn(config.Domain))
		}
		m := &dns.Msg{
			MsgHdr: dns.MsgHdr{
				RecursionDesired: false,
			},
			Question: make([]dns.Question, 1),
		}
		c := &dns.Client{
			ReadTimeout: DefaultTimeout,
		}
		var success bool
		var numNS int
		for _, ans := range r.Answer {
			switch t := ans.(type) {
			case *dns.NS:
				nameserver := t.Ns
				numNS++
				var ips []string

				ra, err := localQuery(nameserver, dns.TypeA, config.NSServer, config.NSPort)
				if err != nil || ra == nil {
					return fmt.Errorf("Error getting the IPv4 address of %s: %s\n", nameserver, err)
				}
				if ra.Rcode != dns.RcodeSuccess {
					return fmt.Errorf("Error getting the IPv4 address of %s: %s\n", nameserver, dns.RcodeToString[ra.Rcode])
				}
				for _, ansa := range ra.Answer {
					switch ansb := ansa.(type) {
					case *dns.A:
						ips = append(ips, ansb.A.String())
					}
				}
				raaaa, err := localQuery(nameserver, dns.TypeAAAA, config.NSServer, config.NSPort)
				if err != nil || raaaa == nil {
					return fmt.Errorf("Error getting the IPv6 address of %s: %s\n", nameserver, err)
				}
				if raaaa.Rcode != dns.RcodeSuccess {
					return fmt.Errorf("Error getting the IPv6 address of %s: %s\n", nameserver, dns.RcodeToString[raaaa.Rcode])
				}
				for _, ansaaaa := range raaaa.Answer {
					switch tansaaaa := ansaaaa.(type) {
					case *dns.AAAA:
						ips = append(ips, tansaaaa.AAAA.String())
					}
				}
				for _, ip := range ips {
					m.Question[0] = dns.Question{Name: dns.Fqdn(config.FQDN), Qtype: dns.TypeSOA, Qclass: dns.ClassINET}
					m.Id = dns.Id()
					var nsAddressPort string
					if strings.ContainsAny(":", ip) {
						// IPv6 address
						nsAddressPort = "[" + ip + "]:53"
					} else {
						nsAddressPort = ip + ":53"
					}
					soa, _, err := c.Exchange(m, nsAddressPort)
					// TODO: retry if timeout? Otherwise, one lost UDP packet and it is the end
					if err != nil || soa == nil {
						goto Next
					}
					if soa.Rcode != dns.RcodeSuccess {
						goto Next
					}
					if len(soa.Answer) == 0 { // May happen if the server is a recursor, not authoritative, since we query with RD=0
						goto Next
					}
				}
				success = true
			Next:
			}
		}
		if numNS == 0 {
			return fmt.Errorf("No NS records for %q. It is probably a CNAME to a domain but not a zone\n", dns.Fqdn(os.Args[1]))
		}
		if !success {
			return err
		}
		return nil
	}
}
