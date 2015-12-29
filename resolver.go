package libnetwork

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/libnetwork/iptables"
	"github.com/miekg/dns"
)

// Resolver represents the embedded DNS server in Docker. It operates
// by listening on container's loopback interface for DNS queries.
type Resolver interface {
	// Start starts the name server for the container
	Start() error
	// Stop stops the name server for the container
	Stop()
	// SetupFunc() provides the setup function that should be run
	// in the container's network namespace.
	SetupFunc() func()
	// NameServer() returns the IP of the DNS resolver for the
	// containers.
	NameServer() string
	// To configure external name servers the resolver should use
	SetExtServers([]string)
}

var (
	resolverIP = "127.0.0.1"
	dnsPort    = "53"
)

// resolver implements the Resolver interface
type resolver struct {
	sb     *sandbox
	extDNS []string
	server *dns.Server
	conn   *net.UDPConn
	err    error
}

// NewResolver creates a new instance of the Resolver
func NewResolver(sb *sandbox) Resolver {
	return &resolver{
		sb:  sb,
		err: fmt.Errorf("Setup not done yet"),
	}
}

func setupNAT(name string, rule ...string) error {
	if output, err := iptables.Raw(rule...); err != nil {
		return fmt.Errorf("Setting up %s failed: %v", name, err)
	} else if len(output) != 0 {
		return fmt.Errorf("Setting up %s failed: %v", name, err)
	}
	return nil
}

func (r *resolver) SetupFunc() func() {
	return (func() {
		var err error

		addr := &net.UDPAddr{
			IP: net.ParseIP(resolverIP),
		}

		r.conn, err = net.ListenUDP("udp", addr)
		if err != nil {
			r.err = fmt.Errorf("Error in opening name server socket %v", err)
			log.Error(r.err)
			return
		}
		laddr := r.conn.LocalAddr()
		ipPort := strings.Split(laddr.String(), ":")

		rules := [][]string{
			{"-t", "nat", "-A", "OUTPUT", "-s", resolverIP, "-p", "udp", "--dport", dnsPort, "-j", "DNAT", "--to-destination", laddr.String()},
			{"-t", "nat", "-A", "POSTROUTING", "-s", resolverIP, "-p", "udp", "--sport", ipPort[1], "-j", "SNAT", "--to-source", ":" + dnsPort},
		}

		for i, rule := range rules {
			r.err = setupNAT("rule "+strconv.Itoa(i), rule...)
			if r.err != nil {
				log.Error(r.err)
				return
			}
		}
		r.err = nil
	})
}

func (r *resolver) Start() error {
	// make sure the resolver has been setup before starting
	if r.err != nil {
		return r.err
	}
	s := &dns.Server{Handler: r, PacketConn: r.conn}
	r.server = s
	go func() {
		s.ActivateAndServe()
	}()
	return nil
}

func (r *resolver) Stop() {
	if r.server != nil {
		r.server.Shutdown()
	}
}

func (r *resolver) SetExtServers(dns []string) {
	r.extDNS = dns
}

func (r *resolver) NameServer() string {
	return resolverIP
}

func (r *resolver) handleIPv4Query(name string, query *dns.Msg) *dns.Msg {
	addr := r.sb.ResolveName(name)
	if addr == nil {
		return nil
	}

	log.Debugf("Lookup for %s: IP %s", name, addr.String())

	resp := new(dns.Msg)
	resp.SetReply(query)

	rr := new(dns.A)
	rr.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1800}
	rr.A = addr
	resp.Answer = append(resp.Answer, rr)
	return resp
}

func (r *resolver) handlePTRQuery(ip string, query *dns.Msg) *dns.Msg {
	name := r.sb.ResolveIP(ip)
	if len(name) == 0 {
		return nil
	}

	log.Debugf("Lookup for IP %s: name %s", ip, name)

	resp := new(dns.Msg)
	resp.SetReply(query)

	rr := new(dns.PTR)
	rr.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 1800}
	rr.Ptr = name
	resp.Answer = append(resp.Answer, rr)
	return resp
}

func (r *resolver) ServeDNS(w dns.ResponseWriter, query *dns.Msg) {
	var (
		resp *dns.Msg
		err  error
	)

	name := query.Question[0].Name
	if query.Question[0].Qtype == dns.TypeA {
		resp = r.handleIPv4Query(name, query)
	} else if query.Question[0].Qtype == dns.TypePTR {
		resp = r.handlePTRQuery(name, query)
	}

	if resp == nil {
		log.Debugf("Querying ext dns %s for %s[%d]", r.extDNS[0], name, query.Question[0].Qtype)

		c := &dns.Client{Net: "udp"}
		addr := fmt.Sprintf("%s:%d", r.extDNS[0], 53)

		// TODO: iterate over avilable servers in case of error
		resp, _, err = c.Exchange(query, addr)
		if err != nil {
			log.Errorf("External resolution failed, %s", err)
			return
		}
	}

	err = w.WriteMsg(resp)
	if err != nil {
		log.Errorf("Error writing resolver resp, %s", err)
	}
}
