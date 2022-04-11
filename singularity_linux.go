package singularity

// Linux Transparent Proxy Support
// https://www.kernel.org/doc/Documentation/networking/tproxy.txt
// e.g. `sudo iptables -t mangle -I PREROUTING -d ext_ip_address
// -p tcp --dport 8080 -j TPROXY --on-port=80 --on-ip=ext_ip_address
// will redirect external port 8080 on port 80 of Singularity

func useIPTransparent(network, address string, conn syscall.RawConn) error {
	return conn.Control(func(descriptor uintptr) {
		syscall.SetsockoptInt(int(descriptor), syscall.IPPROTO_IP, syscall.IP_TRANSPARENT, 1)
	})
}
