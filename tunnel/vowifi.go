package tunnel

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// VoWiFiProxy — Transparent UDP NAT for Wi-Fi Calling (IPSec/IKEv2)
//
// Because the VPN intercepts all traffic, VoWiFi packets (UDP 500/4500)
// are captured by the TUN interface. If we simply write them back to TUN,
// Android receives them as INBOUND packets from the VPN and drops them.
//
// This proxy creates real, protected UDP sockets bound to the physical network,
// acting as a NAT to route VoWiFi traffic securely without VPN interference.
// ─────────────────────────────────────────────────────────────────────────────

type VoWiFiProxy struct {
	engine  *Engine
	tunFile *os.File
	mu      sync.Mutex
	conns   map[string]*net.UDPConn
}

func NewVoWiFiProxy(engine *Engine, tunFile *os.File) *VoWiFiProxy {
	return &VoWiFiProxy{
		engine:  engine,
		tunFile: tunFile,
		conns:   make(map[string]*net.UDPConn),
	}
}

// Route handles an outbound VoWiFi packet from the TUN interface.
func (p *VoWiFiProxy) Route(packet []byte, length int) {
	// Parse the packet to get IPs and Ports.
	// We reuse ParseTUNPacket because it extracts exactly what we need
	// (SrcIP, DstIP, SrcPort, DstPort, and UDP payload).
	queryInfo := ParseTUNPacket(packet, length)
	if queryInfo == nil {
		return
	}

	// Unique session key for NAT mapping
	sessionKey := fmt.Sprintf("%s:%d-%s:%d", queryInfo.SourceIP.String(), queryInfo.SourcePort, queryInfo.DestIP.String(), queryInfo.DestPort)

	p.mu.Lock()
	conn, exists := p.conns[sessionKey]
	p.mu.Unlock()

	if !exists {
		// Create new protected UDP connection bound to the physical network
		var err error
		conn, err = p.createProtectedConn(queryInfo.DestIP, queryInfo.DestPort, queryInfo.IsIPv6)
		if err != nil {
			logf("VoWiFiProxy: failed to create protected socket: %v", err)
			return
		}

		p.mu.Lock()
		p.conns[sessionKey] = conn
		p.mu.Unlock()

		logf("VoWiFiProxy: new IPSec/IKEv2 session established -> %s", sessionKey)
		go p.readLoop(sessionKey, conn, queryInfo)
	}

	// Write UDP payload directly to the physical network
	conn.Write(queryInfo.RawDNSPayload)
}

// createProtectedConn opens a UDP socket to the destination and protects it
// using Android's VpnService.protect() to prevent routing loops.
func (p *VoWiFiProxy) createProtectedConn(destIP net.IP, destPort uint16, isIPv6 bool) (*net.UDPConn, error) {
	network := "udp4"
	if isIPv6 {
		network = "udp6"
	}
	addr := &net.UDPAddr{
		IP:   destIP,
		Port: int(destPort),
	}

	// DialUDP connects the socket, allowing Read/Write without specifying remote addr again
	conn, err := net.DialUDP(network, nil, addr)
	if err != nil {
		return nil, err
	}

	// Protect socket using the engine's provided protect function
	if p.engine.protectFn != nil {
		rawConn, err := conn.SyscallConn()
		if err == nil {
			rawConn.Control(func(fd uintptr) {
				p.engine.protectFn(int(fd))
			})
		}
	}

	return conn, nil
}

// readLoop listens for UDP responses from the carrier's ePDG, reconstructs
// the necessary IP and UDP headers, and writes them back into the TUN
// interface as inbound traffic to the Android OS.
func (p *VoWiFiProxy) readLoop(sessionKey string, conn *net.UDPConn, origInfo *DNSQueryInfo) {
	defer func() {
		conn.Close()
		p.mu.Lock()
		delete(p.conns, sessionKey)
		p.mu.Unlock()
		logf("VoWiFiProxy: IPSec/IKEv2 session closed -> %s", sessionKey)
	}()

	buf := make([]byte, 8192)
	for p.engine.IsRunning() {
		// IPSec NAT-T keepalives typically occur every 20-30 seconds.
		// A 5-minute timeout is safe to tear down dead sessions.
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, err := conn.Read(buf)
		if err != nil {
			break
		}

		if n > 0 {
			// Construct inbound IP packet (Swap Source and Dest)
			// Orig  (Outbound): Src=Phone, Dst=Carrier
			// Reply (Inbound):  Src=Carrier, Dst=Phone
			var respPacket []byte
			if origInfo.IsIPv6 {
				respPacket = buildIPv6UDPPacket(origInfo.DestIP, origInfo.SourceIP, origInfo.DestPort, origInfo.SourcePort, buf[:n])
			} else {
				respPacket = buildIPv4UDPPacket(origInfo.DestIP, origInfo.SourceIP, origInfo.DestPort, origInfo.SourcePort, buf[:n])
			}

			p.tunFile.Write(respPacket)
		}
	}
}
