package singularity

import (
	"fmt"
	"log"
	"os/exec"
	"strconv"
)

// IPTablesRule is a struct representing a linux iptable firewall rule
type IPTablesRule struct {
	srcAddr      string
	srcPort      string
	dstAddr      string
	dstPort      string
	srcPortRange string
	v6           bool
}

// NewIPTableRule populate an iptables rule
func NewIPTableRule(srcAddr string, srcPort string,
	dstAddr string, dstPort string, v6 bool) *IPTablesRule {
	p := IPTablesRule{srcAddr: srcAddr, srcPort: srcPort,
		dstAddr: dstAddr, dstPort: dstPort, v6: v6}
	p.generateSourcePortRange(10)
	return &p
}

// TODO Experimental
func (ipt *IPTablesRule) generateSourcePortRange(max int) {
	i, err := strconv.Atoi(ipt.srcPort)
	if err != nil {
		log.Fatal(err)
	}

	if (i < 0) || (i > 65535) {
		log.Fatal("Source port is not within an expected range")
	}

	maxPort := i + max
	var maxPortString string
	if maxPort > 65535 {
		maxPortString = "65535"
	} else {
		maxPortString = strconv.Itoa(maxPort)
	}
	ipt.srcPortRange = fmt.Sprintf("%v:%v", ipt.srcPort, maxPortString)

}

func (ipt *IPTablesRule) makeAndRunRule(command string) {
	iptables := "/sbin/iptables"
	if ipt.v6 {
		iptables = "/usr/sbin/ip6tables"
	}
	rule := exec.Command(iptables,
		command, "INPUT", "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset",
		"--source", ipt.srcAddr, //"--sport" srcPortRange,
		"--destination", ipt.dstAddr, "--destination-port", ipt.dstPort)
	err := rule.Run()
	log.Printf("Firewall: `iptables` finished with return code: %v", err)
}

// AddRule adds an iptables rule in Linux iptable
func (ipt *IPTablesRule) AddRule() {
	ipt.makeAndRunRule("-A")
}

// RemoveRule removes an iptables rule in Linux iptable
func (ipt *IPTablesRule) RemoveRule() {
	ipt.makeAndRunRule("-D")
}
