package tunnel

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// AdBlockChecker is the interface the MITM proxy uses to query the ad-block
// engine. It mirrors the Engine's own blocking logic (Bloom → Trie → Custom
// Rules) so the proxy can reject ad domains at the TCP level before ever
// dialling the upstream server.
type adBlockChecker interface {
	// IsDomainBlocked returns true if the given hostname (no port) should be
	// blocked according to the ad/security filter lists + custom rules.
	IsDomainBlocked(host string) bool

	// lookupIP resolves a domain to an IP address using the internal resolver.
	lookupIP(host string) (net.IP, error)
}

// ─────────────────────────────────────────────────────────────────────────────
// MITM Proxy — Smart HTTPS proxy for cosmetic ad filtering.
//
// Runs on 127.0.0.1:8080. The Kotlin VpnService routes browser traffic here.
//
// Decision flow for CONNECT requests:
//   1. MitmFilter.IsInterceptionAllowed(host)?
//      NO  → ForwardDirect (raw TCP tunnel, no decryption)
//      YES → Attempt MITM TLS handshake
//              ├── Handshake OK   → Inject cosmetic CSS into HTML responses
//              └── Handshake FAIL → Auto-blacklist domain, forward direct
//
// Resource management:
//   • 5s dial timeout (fast fail for unreachable servers)
//   • 30s idle timeout
//   • 3min max connection lifetime
//   • sync.WaitGroup for clean shutdown
// ─────────────────────────────────────────────────────────────────────────────

const (
	dialTimeout     = 5 * time.Second  // Short! Fail fast on Android.
	idleTimeout     = 30 * time.Second
	maxConnLifetime = 3 * time.Minute
	proxyReadBuf    = 32 * 1024 // 32KB read buffer
)

// MitmProxy is the local HTTPS MITM proxy server.
type MitmProxy struct {
	mu       sync.Mutex
	listener net.Listener
	certMgr  *CertManager
	filter   *MitmFilter
	blocker  adBlockChecker // nil = no ad-blocking at proxy level
	running  bool
	wg       sync.WaitGroup

	// Stats
	proxyBlocked atomic.Int64
}

// NewMitmProxy creates a new MITM proxy with a persistent Root CA.
// certDir is the directory where ca.crt and ca.key are stored.
func NewMitmProxy(certDir string) (*MitmProxy, error) {
	cm, err := NewCertManager(certDir)
	if err != nil {
		return nil, fmt.Errorf("init cert manager: %w", err)
	}
	// Pre-generate TLS cert for the local asset server so the first
	// request doesn't incur cert-generation latency.
	cm.WarmLocalAssetCert()

	return &MitmProxy{
		certMgr: cm,
		filter:  NewMitmFilter(),
	}, nil
}

// GetCACertPEM returns the PEM-encoded Root CA cert for user installation.
func (p *MitmProxy) GetCACertPEM() string {
	return p.certMgr.GetCACertPEM()
}

// GetFilter returns the MitmFilter for UID configuration.
func (p *MitmProxy) GetFilter() *MitmFilter {
	return p.filter
}

// setAdBlockChecker injects the ad-block engine so the proxy can reject
// domains dynamically.
func (p *MitmProxy) setAdBlockChecker(checker adBlockChecker) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.blocker = checker
}

// GetProxyBlockedCount returns how many requests the proxy rejected via the
// ad-block gate (useful for stats / debugging).
func (p *MitmProxy) GetProxyBlockedCount() int64 {
	return p.proxyBlocked.Load()
}

// Listen binds the TCP listener synchronously. Call this BEFORE configuring
// HTTP proxy routing in the VPN so the port is guaranteed to be open.
func (p *MitmProxy) Listen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	p.mu.Lock()
	p.listener = ln
	p.running = true
	p.mu.Unlock()

	logf("MITM Proxy: listening on %s", addr)
	return nil
}

// Serve runs the accept loop. This function blocks; call it in a goroutine
// AFTER Listen() has returned successfully.
func (p *MitmProxy) Serve() error {
	p.mu.Lock()
	ln := p.listener
	p.mu.Unlock()

	if ln == nil {
		return fmt.Errorf("Serve called before Listen")
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			p.mu.Lock()
			running := p.running
			p.mu.Unlock()
			if !running {
				return nil // Clean shutdown
			}
			logf("MITM Proxy: accept error: %v", err)
			continue
		}

		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.handleConnection(conn)
		}()
	}
}

// Stop gracefully shuts down the proxy.
func (p *MitmProxy) Stop() {
	p.mu.Lock()
	p.running = false
	if p.listener != nil {
		p.listener.Close()
	}
	p.mu.Unlock()

	// Wait for active connections to finish (with timeout)
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logf("MITM Proxy: stopped gracefully (auto-blacklisted %d domains)", p.filter.GetBlacklistCount())
	case <-time.After(10 * time.Second):
		logf("MITM Proxy: force-stopped (timeout)")
	}
	logf("MITM Proxy: blocked %d ad requests at proxy level", p.proxyBlocked.Load())
}

// ── Connection Handling ──────────────────────────────────────────────────────

func (p *MitmProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Set max lifetime on the client connection
	clientConn.SetDeadline(time.Now().Add(maxConnLifetime))

	// Set a short read deadline for the initial HTTP header parsing.
	// This prevents goroutine leaks from stalled/slow connections (Slowloris).
	clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Read the HTTP request
	reader := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return // Invalid or timed-out request, just close
	}

	// Reset the deadline back to the full connection lifetime
	clientConn.SetReadDeadline(time.Time{})

	if req.Method == http.MethodConnect {
		p.handleConnect(clientConn, req)
	} else {
		p.handleHTTP(clientConn, req)
	}
}

// handleConnect processes HTTPS CONNECT requests.
// 3-tier decision flow:
//   Gate 1 — BLOCK:        Domain is in ad/security filter lists → 403 immediately.
//   Gate 2 — PASS-THROUGH: Domain is sensitive (banking, cert-pinned) → raw TCP tunnel.
//   Gate 3 — MITM:         Domain is safe to intercept → decrypt + inject scripts/CSS.
func (p *MitmProxy) handleConnect(clientConn net.Conn, req *http.Request) {
	host := req.Host

	// Normalize host (add default port if missing)
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	hostname := hostOnly(host)

	// ── Guard: Block loopback/internal addresses to prevent SSRF ──────
	if isLoopbackOrInternal(hostname) {
		writeHTTPError(clientConn, 403, "Blocked: loopback address")
		return
	}

	// ── Gate 1: BLOCK — ad/tracker domain? Drop immediately. ──────────
	// NOTE: Ad blocking applies to ALL apps, not just browsers.
	if p.blocker != nil && p.blocker.IsDomainBlocked(hostname) {
		p.proxyBlocked.Add(1)
		writeHTTPError(clientConn, 403, "Blocked by BlockAds")
		return
	}

	// ── Gate 2: UID CHECK — only intercept selected browsers ──────────
	// On Android 10+ (API 29+), /proc/net/tcp is blocked by SELinux so
	// resolveConnUID returns -1. In that case, we trust the VPN layer
	// which already routes only selected browser traffic to this proxy.
	// We only reject if we can positively confirm the UID is NOT allowed.
	sourceUID := resolveConnUID(clientConn)
	if sourceUID >= 0 && p.filter.HasAllowedUIDs() && !p.filter.IsUIDAllowed(sourceUID) {
		// Positively identified as a non-browser app → pass-through
		p.forwardDirect(clientConn, host)
		return
	}

	// ── Gate 3: PASS-THROUGH — sensitive / cert-pinned domain ─────────
	if !p.filter.IsInterceptionAllowed(hostname) {
		// Direct tunnel — no decryption
		p.forwardDirect(clientConn, host)
		return
	}

	// ── Gate 3a: LOCAL ASSET SERVER — serve from memory ───────────────
	if IsLocalAssetHost(hostname) {
		p.serveLocalAssetDirect(clientConn, hostname)
		return
	}

	// ── Gate 3b: MITM — decrypt + inject cosmetic CSS ──
	p.mitmIntercept(clientConn, host, hostname)
}

// forwardDirect creates a raw TCP tunnel (no TLS interception).
func (p *MitmProxy) forwardDirect(clientConn net.Conn, host string) {
	dialAddr, resolveErr := p.resolveDialAddr(host)
	if resolveErr != nil {
		writeHTTPError(clientConn, 502, "Upstream DNS: unresolvable")
		return
	}

	// Connect to the real server
	serverConn, err := net.DialTimeout("tcp", dialAddr, dialTimeout)
	if err != nil {
		writeHTTPError(clientConn, 502, "Bad Gateway")
		return
	}
	defer serverConn.Close()

	// Send 200 OK to tell the client the tunnel is established
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Bidirectional copy with timeout management
	serverConn.SetDeadline(time.Now().Add(maxConnLifetime))
	bidirectionalCopy(clientConn, serverConn)
}

// mitmIntercept performs TLS interception with handshake fail-safe.
// If the client TLS handshake fails (cert pinning), the domain is
// automatically blacklisted for all future requests.
func (p *MitmProxy) mitmIntercept(clientConn net.Conn, host, hostname string) {
	dialAddr, resolveErr := p.resolveDialAddr(host)
	if resolveErr != nil {
		// DNS couldn't resolve the host. Typically means the user's
		// upstream DNS is filtering the domain (AdGuard DNS / NextDNS /
		// Pi-hole returning NXDOMAIN). Returning 502 cleanly is correct —
		// we can't tunnel to an unresolvable host, and a fallback via
		// the system resolver would fail the same way.
		writeHTTPError(clientConn, 502, "Upstream DNS: unresolvable")
		return
	}

	// Connect to the real server first (verify it's reachable)
	serverConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: dialTimeout},
		"tcp", dialAddr,
		&tls.Config{
			ServerName:         hostname,
			InsecureSkipVerify: false,
		},
	)
	if err != nil {
		// Dial to a resolved IP failed — the upstream is unreachable or
		// presented an invalid cert. Fall back to a raw passthrough so
		// the client can try to reach it directly instead of seeing 502.
		logf("MITM: server TLS dial to %s failed, falling back to direct: %v", host, err)
		p.forwardDirect(clientConn, host)
		return
	}
	defer serverConn.Close()
	serverConn.SetDeadline(time.Now().Add(maxConnLifetime))

	// Tell the client the tunnel is established
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Get the shared dynamic TLS config (handles SNI & caching & singleflight internally)
	tlsConfig := p.certMgr.GetDynamicTLSConfigForHost(hostname)

	// ── Handshake Fail-Safe ──────────────────────────────────────────
	// TLS handshake with the client using our dynamic cert.
	// If the client rejects it (cert pinning), we auto-blacklist this domain.
	clientTLS := tls.Server(clientConn, tlsConfig)
	if err := clientTLS.Handshake(); err != nil {
		// *** CERT PINNING DETECTED ***
		// The client app rejected our CA-signed cert.
		// Auto-blacklist this domain so future requests go direct.
		errStr := err.Error()
		if strings.Contains(errStr, "unknown certificate") ||
			strings.Contains(errStr, "handshake failure") ||
			strings.Contains(errStr, "certificate unknown") ||
			strings.Contains(errStr, "bad certificate") ||
			strings.Contains(errStr, "tls:") {
			p.filter.BlacklistDomain(hostname)
		}
		logf("MITM: client handshake failed for %s (auto-blacklisted): %v", hostname, err)
		return
	}
	defer clientTLS.Close()

	// Handshake succeeded! Relay HTTP with cosmetic CSS injection.
	p.relayHTTP(clientTLS, serverConn, hostname)
}

// serveLocalAssetDirect handles CONNECT requests to local.pwhs.app.
// Instead of dialling an upstream server, it performs the TLS handshake
// with the client using a dynamically generated cert and then serves
// assets directly from memory.
func (p *MitmProxy) serveLocalAssetDirect(clientConn net.Conn, hostname string) {
	// Tell the client the tunnel is established
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Get the shared dynamic TLS config (handles SNI & caching & singleflight internally)
	tlsConfig := p.certMgr.GetDynamicTLSConfigForHost(hostname)

	// TLS handshake with the client
	clientTLS := tls.Server(clientConn, tlsConfig)
	if err := clientTLS.Handshake(); err != nil {
		logf("Local asset server: TLS handshake failed: %v", err)
		return
	}
	defer clientTLS.Close()

	// Serve HTTP requests from memory (no upstream connection needed)
	clientReader := bufio.NewReader(clientTLS)
	for {
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			return // Client closed or error
		}

		resp := ServeLocalAsset(req)
		if err := resp.Write(clientTLS); err != nil {
			return
		}

		if req.Close {
			return
		}
	}
}

// relayHTTP relays HTTP request/response pairs between the MITM'd client
// and the real server, injecting cosmetic CSS into HTML responses.
// Also applies Gate 1 (ad-blocking) to individual sub-requests within the
// MITM'd TLS session (e.g., tracker scripts loaded as sub-resources).
func (p *MitmProxy) relayHTTP(clientConn net.Conn, serverConn net.Conn, hostname string) {
	clientReader := bufio.NewReader(clientConn)
	serverReader := bufio.NewReader(serverConn)

	for {
		// Read request from client
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			return // Client closed or error
		}

		// Set Host header if missing
		if req.Host == "" {
			req.Host = hostname
		}

		// ── Sub-request Block Gate ────────────────────────────────────
		// Even inside an MITM'd connection, individual sub-requests may
		// target ad/tracker domains (via Host header). Block them here.
		reqHost := hostOnly(req.Host)

		// ── Local Asset Server sub-request ──────────────────────────
		// If the browser requests local.pwhs.app resources inside
		// an existing MITM'd connection, serve from memory inline.
		if IsLocalAssetHost(reqHost) {
			resp := ServeLocalAsset(req)
			resp.Write(clientConn)
			continue
		}

		if p.blocker != nil && reqHost != hostname && p.blocker.IsDomainBlocked(reqHost) {
			p.proxyBlocked.Add(1)
			// Write a minimal HTTP 403 response inline (don't close the connection)
			blockedResp := &http.Response{
				StatusCode: 403,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("Blocked by BlockAds")),
			}
			blockedResp.Header.Set("Connection", "keep-alive")
			blockedResp.Header.Set("Content-Length", "19")
			blockedResp.Write(clientConn)
			continue
		}

		// Strip Accept-Encoding on HTML navigations so the response body
		// arrives uncompressed and the injector can find <head in plaintext.
		// Subresources (JS, CSS, images, fonts) keep compression —
		// dramatically reducing bandwidth on heavy sites.
		if requestAcceptsHTML(req) {
			req.Header.Del("Accept-Encoding")
		}

		if err := req.Write(serverConn); err != nil {
			return
		}

		// Read response from server
		resp, err := http.ReadResponse(serverReader, req)
		if err != nil {
			return
		}

		// If this is an HTML response, attempt injection. Decompresses
		// gzip/deflate bodies transparently; brotli responses pass
		// through uninjected (no stdlib decoder).
		if ShouldInjectHTML(resp.Header.Get("Content-Type")) {
			wrapResponseForInjection(resp)
		}

		// Write response to client
		if err := resp.Write(clientConn); err != nil {
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		// Check if the connection should be closed
		if resp.Close || req.Close {
			return
		}
	}
}

// requestAcceptsHTML returns true when the request's Accept header
// explicitly includes text/html — i.e., the client is requesting an HTML
// document, not a subresource. Used to decide when to strip
// Accept-Encoding so responses arrive uncompressed for injection.
func requestAcceptsHTML(req *http.Request) bool {
	accept := req.Header.Get("Accept")
	return strings.Contains(strings.ToLower(accept), "text/html")
}

// wrapResponseForInjection prepares an HTML response for in-stream <link>
// injection. It transparently decompresses gzip/deflate bodies so the
// injector can find <head in plaintext, strips Content-Security-Policy
// (which would otherwise block the injected <link href="https://local.pwhs.app/...">),
// and clears framing headers so Go re-emits the modified body as
// chunked plaintext. If the body uses an encoding we cannot decode
// (brotli, compress, or anything else), the function returns without
// modifying the response and injection is skipped — the page still
// renders correctly, just without cosmetic filtering.
func wrapResponseForInjection(resp *http.Response) {
	encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))

	var bodyReader io.Reader
	switch encoding {
	case "", "identity":
		bodyReader = resp.Body
	case "gzip":
		gr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return // malformed gzip — pass through as-is
		}
		bodyReader = gr
	case "deflate":
		// HTTP Content-Encoding: deflate is historically ambiguous: some
		// servers send zlib-wrapped (RFC 1950), others send raw DEFLATE
		// (RFC 1951). Try zlib first (most servers), fall back to raw
		// flate. Buffer the body so we can re-read on fallback.
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			return
		}
		if zr, err := zlib.NewReader(bytes.NewReader(raw)); err == nil {
			bodyReader = zr
		} else {
			bodyReader = flate.NewReader(bytes.NewReader(raw))
		}
	default:
		// brotli, compress, or other unsupported encoding — pass through
		// without injection rather than corrupt the body by stripping
		// Content-Encoding from data we can't actually decode.
		return
	}

	resp.Body = io.NopCloser(NewInjectingReader(bodyReader))
	resp.ContentLength = -1
	resp.Header.Del("Content-Length")
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Transfer-Encoding")
	// CSP would block the injected <link>/<script> from the local asset host.
	resp.Header.Del("Content-Security-Policy")
	resp.Header.Del("Content-Security-Policy-Report-Only")
	resp.TransferEncoding = nil
	resp.Uncompressed = true
}

// handleHTTP handles plain HTTP requests (non-CONNECT).
func (p *MitmProxy) handleHTTP(clientConn net.Conn, req *http.Request) {
	host := req.Host
	if !strings.Contains(host, ":") {
		host = host + ":80"
	}

	hostname := hostOnly(host)

	// ── Gate 1: BLOCK — ad/tracker domain? Drop immediately. ──────────
	if p.blocker != nil && p.blocker.IsDomainBlocked(hostname) {
		p.proxyBlocked.Add(1)
		writeHTTPError(clientConn, 403, "Blocked by BlockAds")
		return
	}

	dialAddr, resolveErr := p.resolveDialAddr(host)
	if resolveErr != nil {
		writeHTTPError(clientConn, 502, "Upstream DNS: unresolvable")
		return
	}
	serverConn, err := net.DialTimeout("tcp", dialAddr, dialTimeout)
	if err != nil {
		writeHTTPError(clientConn, 502, "Bad Gateway")
		return
	}
	defer serverConn.Close()
	serverConn.SetDeadline(time.Now().Add(maxConnLifetime))

	// Strip Accept-Encoding on HTML navigations so injection can find <head.
	if requestAcceptsHTML(req) {
		req.Header.Del("Accept-Encoding")
	}

	if err := req.Write(serverConn); err != nil {
		return
	}

	serverReader := bufio.NewReader(serverConn)
	resp, err := http.ReadResponse(serverReader, req)
	if err != nil {
		return
	}

	if ShouldInjectHTML(resp.Header.Get("Content-Type")) {
		wrapResponseForInjection(resp)
	}

	resp.Write(clientConn)
	resp.Body.Close()
}

// ── Utilities ────────────────────────────────────────────────────────────────

// resolveDialAddr uses the Engine's DNS resolver to get the IP for the host
// and returns a host:port string safe to hand to net.Dial.
//
// On Android, the Go tunnel process is excluded from the VPN via
// addDisallowedApplication, but Android still routes DNS queries from
// those processes through the VPN's configured DNS on many devices —
// which can't be reached from a socket that bypasses the VPN. The result
// is that Go's built-in net.DialTimeout("tcp", "hostname:443") returns
// "no such host" even for popular domains. To avoid that failure mode
// this function refuses to return a bare hostname: if the internal
// resolver cannot resolve the host, it returns an error instead of
// letting Go fall through to its broken system resolver. Callers are
// expected to surface the error to the HTTP client as a 502.
func (p *MitmProxy) resolveDialAddr(hostport string) (string, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport, nil // no port; let the dialer handle it
	}

	// Already a literal IP → no DNS needed.
	if net.ParseIP(host) != nil {
		return hostport, nil
	}

	if p.blocker == nil {
		// No internal resolver available — fall through to the dialer
		// (only used in tests; production always wires a blocker).
		return hostport, nil
	}

	resolvedIP, err := p.blocker.lookupIP(host)
	if err != nil || resolvedIP == nil {
		return "", fmt.Errorf("resolve %s: %w", host, err)
	}
	return net.JoinHostPort(resolvedIP.String(), port), nil
}

// bidirectionalCopy copies data between two connections in both directions.
// It waits for BOTH directions to finish before returning. When one side
// EOFs, the corresponding half of the other connection is closed (TCP
// half-close) so the peer can drain its remaining data before the caller's
// deferred Close() runs. Without this, downloads truncate and TLS sessions
// reset mid-stream on direct passthrough traffic.
func bidirectionalCopy(a, b net.Conn) {
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(b, a)
		if tcp, ok := b.(interface{ CloseWrite() error }); ok {
			tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(a, b)
		if tcp, ok := a.(interface{ CloseWrite() error }); ok {
			tcp.CloseWrite()
		}
		done <- struct{}{}
	}()

	<-done
	<-done
}

// writeHTTPError writes an HTTP error response.
func writeHTTPError(w net.Conn, code int, msg string) {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", code, msg, len(msg), msg)
	w.Write([]byte(resp))
}

// hostOnly strips the port from a host:port string.
func hostOnly(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}

// isLoopbackOrInternal returns true if the hostname is a literal loopback
// or private/internal IP address. This prevents the proxy from connecting
// back to itself (SSRF infinite loop) or reaching internal network services.
// NOTE: We intentionally do NOT call net.LookupHost() here because the app
// is excluded from VPN and system DNS resolution times out. Checking literal
// IPs and well-known names is sufficient for SSRF protection.
func isLoopbackOrInternal(hostname string) bool {
	lower := strings.ToLower(hostname)
	if lower == "localhost" || lower == "0.0.0.0" || lower == "::" {
		return true
	}

	ip := net.ParseIP(hostname)
	if ip == nil {
		return false // Not a literal IP — allow it (will be resolved later via internal DNS)
	}

	return ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || isPrivateIP(ip)
}

// isPrivateIP checks if an IP is in RFC 1918 private ranges.
func isPrivateIP(ip net.IP) bool {
	privateRanges := []struct {
		network string
	}{
		{"10.0.0.0/8"},
		{"172.16.0.0/12"},
		{"192.168.0.0/16"},
	}
	for _, r := range privateRanges {
		_, cidr, _ := net.ParseCIDR(r.network)
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
