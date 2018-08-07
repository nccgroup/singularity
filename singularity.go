package singularity

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

/*** General Stuff ***/

// DNSClientStateStore stores DNS sessions
// It permits to respond to multiple clients
// based on their current DNS rebinding state.
// Must use RO or RW mutex to access.
type DNSClientStateStore struct {
	Sessions map[string]*DNSClientState
	sync.RWMutex
}

// AppConfig stores running parameter of singularity server.
type AppConfig struct {
	HTTPServerPorts              []int
	ResponseIPAddr               string
	ResponseReboundIPAddr        string
	RebindingFn                  func(session string, dcss *DNSClientStateStore, q dns.Question) string
	ResponseReboundIPAddrtimeOut int
	AllowDynamicHTTPServers      bool
}

/*** DNS Stuff ***/

// DNSClientState holds the current rebinding state of client.
type DNSClientState struct {
	LastQueryTime                time.Time
	CurrentQueryTime             time.Time
	ResponseIPAddr               string
	ResponseReboundIPAddr        string
	LastResponseReboundIPAddr    int
	ResponseReboundIPAddrtimeOut int
	DNSCacheFlush                bool
}

// ExpireOldEntries expire DNS Client Sessions
// that existed longer than duration
// Old entries are expire at a provided interval
// Someone could possibly fill memory before old entries are expired
func (dcss *DNSClientStateStore) ExpireOldEntries(duration time.Duration) {
	dcss.Lock()
	for sk, sv := range dcss.Sessions {
		diff := time.Since(sv.LastQueryTime)
		if (!sv.LastQueryTime.IsZero()) && (diff > duration) {
			delete(dcss.Sessions, sk)
		}
	}
	dcss.Unlock()
}

// DNSQuery is a convenience structure to hold
// the parsed DNS query of a client.
type DNSQuery struct {
	ResponseIPAddr        string
	ResponseReboundIPAddr string
	Session               string
	DNSCacheFlush         bool
	Domain                string
}

// NewDNSQuery parses DNS query string
// and returns a DNSQuery structure.
func NewDNSQuery(qname string) (*DNSQuery, error) {
	name := new(DNSQuery)

	split := strings.Split(qname, "-e.")

	if len(split) == 1 {
		return name, errors.New("cannot find end tag in DNS query")
	}

	head := split[0]

	tail := strings.Split(head, "s-")

	if len(tail) == 1 {
		return name, errors.New("cannot find start tag in DNS query")
	}

	elements := strings.Split(tail[1], "-")

	domainSuffix := split[1]

	if (len(domainSuffix) < 3) && (strings.ContainsAny(domainSuffix, ".") == false) {
		return name, errors.New("cannot parse domain in DNS query")
	}

	if len(elements) != 4 {
		return name, errors.New("cannot parse DNS query")
	}

	if net.ParseIP(elements[0]) == nil {
		return name, errors.New("cannot parse IP address of first host in DNS query")

	}
	name.ResponseIPAddr = elements[0]

	if elements[1] != "localhost" {

		if net.ParseIP(elements[1]) == nil {
			return name, errors.New("cannot parse IP address of second host in DNS query")

		}
	}
	name.ResponseReboundIPAddr = elements[1]

	name.Session = elements[2]

	if len(name.Session) == 0 {
		return name, errors.New("cannot parse session in DNS query")

	}

	if len(elements[3]) != 0 {
		name.DNSCacheFlush = true
	}

	name.Domain = fmt.Sprintf(".%v", domainSuffix)

	return name, nil
}

// dnsRebindFirst is a convenience function
// that always returns the first host in DNS query
func dnsRebindFirst(session string, dcss *DNSClientStateStore, q dns.Question) string {
	var result string
	dcss.RLock()
	result = dcss.Sessions[session].ResponseIPAddr
	dcss.RUnlock()
	return result
}

// DNSRebindFromQueryFirstThenSecond is a response handler to DNS queries
// It extracts the hosts in the DNS query string
// It first returns the first host once in the DNS query string
// then the second host in all subsequent queries for a period of time timeout.
func DNSRebindFromQueryFirstThenSecond(session string, dcss *DNSClientStateStore, q dns.Question) string {
	dcss.RLock()
	host := dcss.Sessions[session].ResponseIPAddr
	dnsCacheFlush := dcss.Sessions[session].DNSCacheFlush
	elapsed := dcss.Sessions[session].CurrentQueryTime.Sub(dcss.Sessions[session].LastQueryTime)
	timeOut := dcss.Sessions[session].ResponseReboundIPAddrtimeOut

	log.Printf("In DNSRebindFromQueryFirstThenSecond\n")

	if dnsCacheFlush == false { // This is not a request for cache eviction
		if elapsed < (time.Second * time.Duration(timeOut)) {
			host = dcss.Sessions[session].ResponseReboundIPAddr
		}
	}
	dcss.RUnlock()
	return host
}

// DNSRebindFromQueryRandom is a response handler to DNS queries
// It extracts the two hosts in the DNS query string
// then returns either extracted hosts randomly
func DNSRebindFromQueryRandom(session string, dcss *DNSClientStateStore, q dns.Question) string {
	dcss.RLock()
	host := dcss.Sessions[session].ResponseIPAddr
	dnsCacheFlush := dcss.Sessions[session].DNSCacheFlush
	hosts := []string{dcss.Sessions[session].ResponseIPAddr, dcss.Sessions[session].ResponseReboundIPAddr}
	dcss.RUnlock()

	log.Printf("In DNSRebindFromQueryRandom\n")

	if dnsCacheFlush == false { // This is not a request for cache eviction
		host = hosts[rand.Intn(len(hosts))]
	}

	return host
}

// DNSRebindFromQueryRoundRobin is a response handler to DNS queries
// It extracts the two hosts in the DNS query string
// then returns the extracted hosts in a round robin fashion
func DNSRebindFromQueryRoundRobin(session string, dcss *DNSClientStateStore, q dns.Question) string {
	dcss.RLock()
	host := dcss.Sessions[session].ResponseIPAddr
	dnsCacheFlush := dcss.Sessions[session].DNSCacheFlush
	ResponseIPAddr := dcss.Sessions[session].ResponseIPAddr
	ResponseReboundIPAddr := dcss.Sessions[session].ResponseReboundIPAddr
	LastResponseReboundIPAddr := dcss.Sessions[session].LastResponseReboundIPAddr
	dcss.RUnlock()

	log.Printf("In DNSRebindFromQueryRoundRobin\n")

	if dnsCacheFlush == false { // This is not a request for cache eviction
		hosts := []string{"", ResponseIPAddr, ResponseReboundIPAddr}
		switch LastResponseReboundIPAddr {
		case 0:
			LastResponseReboundIPAddr = 1
		case 1:
			LastResponseReboundIPAddr = 2
		case 2:
			LastResponseReboundIPAddr = 1
		}
		dcss.Lock()
		dcss.Sessions[session].LastResponseReboundIPAddr = LastResponseReboundIPAddr
		dcss.Unlock()
		host = (hosts[LastResponseReboundIPAddr])
	}

	return host
}

// MakeRebindDNSHandler generates a DNS request handler
// based on app settings.
// This is the core DNS queries handling loop
func MakeRebindDNSHandler(appConfig *AppConfig, dcss *DNSClientStateStore) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		name := &DNSQuery{}
		clientState := &DNSClientState{}
		now := time.Now()
		rebindingFn := appConfig.RebindingFn

		m := new(dns.Msg)
		m.SetReply(r)
		m.Compress = false

		switch r.Opcode {
		case dns.OpcodeQuery:
			for _, q := range m.Question {
				switch q.Qtype {
				case dns.TypeA:
					log.Printf("Received A query: %v\n", q.Name)

					// Preparing to update the client DNS query state
					clientState.CurrentQueryTime = now
					clientState.ResponseReboundIPAddrtimeOut = appConfig.ResponseReboundIPAddrtimeOut
					clientState.DNSCacheFlush = false

					var err error
					name, err = NewDNSQuery(q.Name)
					log.Printf("Parsed query: %v, error: %v\n", name, err)

					if err != nil {
						// We could not parse the query, set default response settings
						clientState.ResponseIPAddr = appConfig.ResponseIPAddr
						clientState.ResponseReboundIPAddr = appConfig.ResponseReboundIPAddr
						// Strategy is to return clientState.ResponseIPAddr
						rebindingFn = dnsRebindFirst
					} else {
						clientState.ResponseIPAddr = name.ResponseIPAddr
						clientState.ResponseReboundIPAddr = name.ResponseReboundIPAddr
						clientState.DNSCacheFlush = name.DNSCacheFlush
					}

					_, keyExists := dcss.Sessions[name.Session]
					log.Printf("Session exists: %v\n", keyExists)

					dcss.Lock()
					if keyExists != true {
						// New session
						dcss.Sessions[name.Session] = clientState
					} else {
						// Existing session
						dcss.Sessions[name.Session].ResponseIPAddr = clientState.ResponseIPAddr
						dcss.Sessions[name.Session].ResponseReboundIPAddr = clientState.ResponseReboundIPAddr
					}
					dcss.Sessions[name.Session].DNSCacheFlush = clientState.DNSCacheFlush
					dcss.Unlock()

					host := rebindingFn(name.Session, dcss, q)

					var response string

					if host == "localhost" {

						response = fmt.Sprintf("%s 10 IN CNAME %s.", q.Name, host)

					} else {
						response = fmt.Sprintf("%s 0 IN A %s", q.Name, host)

					}

					dcss.Lock()
					dcss.Sessions[name.Session].CurrentQueryTime = now
					dcss.Sessions[name.Session].LastQueryTime = now
					dcss.Unlock()

					rr, err := dns.NewRR(response)
					if err == nil {
						m.Answer = append(m.Answer, rr)
						log.Printf("Response: %v\n", response)
					}
				}
			}
		}
		w.WriteMsg(m)
	}
}

/*** HTTP Stuff ***/

// DefaultHeadersHandler is a HTTP handler that adds default headers to responses
// for all routes
type DefaultHeadersHandler struct {
	NextHandler http.Handler
}

// HTTPServerStore holds the list of HTTP servers
// Many servers at startup and one (1) dynamically instantianted server
// Access to the servers list must be performed via mutex
type HTTPServerStore struct {
	Errc                    chan HTTPServerError // communicates http server errors
	AllowDynamicHTTPServers bool
	sync.RWMutex
	DynamicServers []*http.Server
	StaticServers  []*http.Server
}

type httpServerInfo struct {
	Port string
}

// HTTPServersConfig is a stucture that is returned
// to JS client to inform about Singularity HTTP ports
// and whether dynamic HTTP server allocation is allowed
type HTTPServersConfig struct {
	ServerInformation       []httpServerInfo
	AllowDynamicHTTPServers bool
}

// HTTP Handler for "/" - Add headers then calls next NextHandler()
func (d *DefaultHeadersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate") // HTTP 1.1
	w.Header().Set("Pragma", "no-cache")                                   // HTTP 1.0
	w.Header().Set("Expires", "0")                                         // Proxies
	w.Header().Set("X-DNS-Prefetch-Control", "off")                        //Chrome
	d.NextHandler.ServeHTTP(w, r)
}

// HTTP Handler for /servers
func (hss *HTTPServerStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	serverInfo := httpServerInfo{}
	emptyResponse, _ := json.Marshal(serverInfo)
	emptyResponseStr := string(emptyResponse)
	serverInfos := make([]httpServerInfo, 0)

	switch r.Method {
	case "GET":

		hss.RLock()
		for _, server := range hss.StaticServers {
			if server != nil {
				staticServerInfo := httpServerInfo{}
				staticServerInfo.Port = strings.Split(server.Addr, ":")[1]
				serverInfos = append(serverInfos, staticServerInfo)
			}
		}
		for _, server := range hss.DynamicServers {
			if server != nil {
				dynamicServerInfo := httpServerInfo{}
				dynamicServerInfo.Port = strings.Split(server.Addr, ":")[1]
				serverInfos = append(serverInfos, dynamicServerInfo)
			}
		}
		hss.RUnlock()

		myHTTPServersConfig := HTTPServersConfig{ServerInformation: serverInfos,
			AllowDynamicHTTPServers: hss.AllowDynamicHTTPServers}

		s, err := json.Marshal(myHTTPServersConfig)

		println(string(s))

		if err != nil {
			http.Error(w, emptyResponseStr, 500)
			return
		}

		fmt.Fprintf(w, "%v", string(s))

	case "PUT":

		if hss.AllowDynamicHTTPServers == false {
			http.Error(w, emptyResponseStr, 400)
			return
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, emptyResponseStr, 400)
			return
		}

		err = json.Unmarshal(body, &serverInfo)
		if err != nil {
			http.Error(w, emptyResponseStr, 400)
			return
		}

		port, err := strconv.Atoi(serverInfo.Port)
		if err != nil {
			http.Error(w, emptyResponseStr, 400)
			return
		}

		hss.Lock()
		if hss.DynamicServers[0] != nil {
			StopHTTPServer(hss.DynamicServers[0], hss)
			hss.DynamicServers[0] = nil
		}
		hss.Unlock()

		httpServer := NewHTTPServer(port, hss)
		httpServerErr := StartHTTPServer(httpServer, hss, true)

		if httpServerErr != nil {
			http.Error(w, emptyResponseStr, 400)
			return
		}

		s, err := json.Marshal(serverInfo)
		if err != nil {
			http.Error(w, emptyResponseStr, 400)
			return
		}

		fmt.Fprintf(w, "%v", string(s))

	default:
		http.Error(w, emptyResponseStr, 400)
		return
	}

}

// NewHTTPServer configures a HTTP server
func NewHTTPServer(port int, hss *HTTPServerStore) *http.Server {
	d := &DefaultHeadersHandler{NextHandler: http.FileServer(http.Dir("./html"))}
	h := http.NewServeMux()

	h.Handle("/", d)
	h.Handle("/servers", hss)

	httpServer := &http.Server{Addr: ":" + strconv.Itoa(port), Handler: h}

	// drop browser connections after delivering
	// so they dont keep socket alive and facilitate rebinding.
	httpServer.SetKeepAlivesEnabled(false)

	return httpServer
}

// HTTPServerError is used to report issues with an HTTP instance
// when started or closed
type HTTPServerError struct {
	Err  error
	Port string
}

// StartHTTPServer starts an HTTP server
// and adds it to  dynamic (if dynamic is true) or static HTTP Store
func StartHTTPServer(s *http.Server, hss *HTTPServerStore, dynamic bool) error {

	var err error

	l, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}

	hss.Lock()
	if dynamic == true {
		found := false
		for _, v := range hss.StaticServers {
			if (v != nil) && (v.Addr == s.Addr) {
				found = true
				break
			}
		}
		if found != true {
			hss.DynamicServers[0] = s
		}

	} else {
		hss.StaticServers = append(hss.StaticServers, s)
	}

	hss.Unlock()

	go func() {
		log.Printf("Starting HTTP Server on %v\n", s.Addr)
		routineErr := s.Serve(l)
		hss.Errc <- HTTPServerError{Err: routineErr, Port: s.Addr}
	}()

	return err

}

// StopHTTPServer stops an HTTP server
func StopHTTPServer(s *http.Server, hss *HTTPServerStore) {
	log.Printf("Stopping HTTP Server on %v\n", s.Addr)
	s.Close()
}
