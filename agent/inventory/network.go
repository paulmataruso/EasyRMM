//go:build !windows

package inventory

import (
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// systemInterfaces lists the machine's network interfaces, without loopback
// and container veth pairs.
func (c Collector) systemInterfaces() ([]agentproto.Interface, error) {
	list, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := []agentproto.Interface{}
	for _, i := range list {
		if i.Flags&net.FlagLoopback != 0 || strings.HasPrefix(i.Name, "veth") {
			continue
		}
		it := agentproto.Interface{Name: i.Name, MAC: i.HardwareAddr.String(), Up: i.Flags&net.FlagUp != 0, Addresses: []string{}}
		if addrs, err := i.Addrs(); err == nil {
			for _, a := range addrs {
				if p, err := netip.ParsePrefix(a.String()); err == nil {
					it.Addresses = append(it.Addresses, p.String())
				}
			}
		}
		if n, err := strconv.Atoi(c.read("/sys/class/net/" + i.Name + "/speed")); err == nil && n > 0 {
			it.SpeedMbps = n
		}
		out = append(out, it)
	}
	return sortInterfaces(out, c.physical), nil
}

// physical reports whether an interface is backed by hardware (a network
// card, or a virtual machine's emulated one) rather than made by software,
// as Docker's bridges are.
func (c Collector) physical(name string) bool {
	_, err := os.Stat(c.path("/sys/class/net/" + name + "/device"))
	return err == nil
}

// gateways reads the default routes from /proc/net/route and
// /proc/net/ipv6_route.
func (c Collector) gateways() []string {
	out := []string{}
	for line := range strings.Lines(c.read("/proc/net/route")) {
		f := strings.Fields(line)
		if len(f) < 3 || f[1] != "00000000" || f[2] == "00000000" {
			continue
		}
		b, err := hex.DecodeString(f[2])
		if err != nil || len(b) != 4 {
			continue
		}
		// The kernel prints the address in host (little-endian) order.
		ip := netip.AddrFrom4([4]byte{b[3], b[2], b[1], b[0]})
		out = appendNew(out, ip.String())
	}
	for line := range strings.Lines(c.read("/proc/net/ipv6_route")) {
		f := strings.Fields(line)
		if len(f) < 5 || f[0] != strings.Repeat("0", 32) || f[1] != "00" || f[4] == strings.Repeat("0", 32) {
			continue
		}
		b, err := hex.DecodeString(f[4])
		if err != nil || len(b) != 16 {
			continue
		}
		out = appendNew(out, netip.AddrFrom16([16]byte(b)).String())
	}
	return out
}

// dns reads the name servers. With systemd-resolved's local stub, the
// servers it forwards to are the useful ones.
func (c Collector) dns() []string {
	servers := nameservers(c.read("/etc/resolv.conf"))
	if len(servers) == 1 && servers[0] == "127.0.0.53" {
		if upstream := nameservers(c.read("/run/systemd/resolve/resolv.conf")); len(upstream) > 0 {
			return upstream
		}
	}
	return servers
}

func nameservers(s string) []string {
	out := []string{}
	for line := range strings.Lines(s) {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if ip, err := netip.ParseAddr(f[1]); err == nil {
				out = appendNew(out, ip.String())
			}
		}
	}
	return out
}
