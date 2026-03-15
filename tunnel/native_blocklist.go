package tunnel

import (
	"strings"
	"sync"
)

// ─────────────────────────────────────────────────────────────────────────────
// Native Blocklist — Hardcoded mobile ad SDK + DoH provider domains.
//
// Web-focused filter lists (EasyList, StevenBlack) miss many mobile ad SDK
// domains used by Unity Ads, AdMob, AppLovin, Vungle, ironSource, etc.
// These are blocked at the DNS layer (Layer 3) so native apps/games that
// bypass the MITM proxy still get their ads killed.
//
// Also blocks DNS-over-HTTPS (DoH) providers so apps can't bypass our
// DnsInterceptor by using encrypted DNS directly.
//
// This blocklist is checked by Engine.isNativeBlocked() and runs in the
// same pipeline as the Trie/Bloom checks — zero overhead for clean domains.
// ─────────────────────────────────────────────────────────────────────────────

// nativeBlocklist holds a set of exact-match and suffix-match domains
// for blocking mobile ad SDKs and DoH providers at the DNS layer.
// Unexported — only used internally by Go Engine, never exposed via gomobile.
type nativeBlocklist struct {
	mu sync.RWMutex

	// exactDomains: map["ads.unity3d.com"] = "mobile_ad"
	exactDomains map[string]string

	// suffixes: []suffixRule{".admob.com", "mobile_ad"}
	// A domain matches if it ends with this suffix OR equals the suffix without
	// the leading dot.
	suffixes []suffixRule
}

type suffixRule struct {
	suffix string // e.g., ".admob.com"
	reason string // e.g., "mobile_ad", "doh_block"
}

// newNativeBlocklist creates the default native blocklist with mobile ad SDK
// and DoH provider domains pre-loaded.
func newNativeBlocklist() *nativeBlocklist {
	bl := &nativeBlocklist{
		exactDomains: make(map[string]string),
	}
	bl.loadDefaults()
	return bl
}

// isBlocked checks if a domain matches the native blocklist.
// Returns (true, reason) if blocked, (false, "") if clean.
func (bl *nativeBlocklist) isBlocked(domain string) (bool, string) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false, ""
	}

	bl.mu.RLock()
	defer bl.mu.RUnlock()

	// Exact match
	if reason, ok := bl.exactDomains[domain]; ok {
		return true, reason
	}

	// Suffix match (wildcard subdomains)
	for _, rule := range bl.suffixes {
		if strings.HasSuffix(domain, rule.suffix) || domain == rule.suffix[1:] {
			return true, rule.reason
		}
	}

	return false, ""
}

// loadDefaults populates the blocklist with known mobile ad SDK and DoH domains.
func (bl *nativeBlocklist) loadDefaults() {
	// ── Mobile Ad SDKs ──────────────────────────────────────────────────

	// Google AdMob / DoubleClick
	bl.addSuffix(".admob.com", "admob")
	bl.addSuffix(".doubleclick.net", "doubleclick")
	bl.addSuffix(".googleadservices.com", "google_ads")
	bl.addSuffix(".googlesyndication.com", "google_ads")
	bl.addSuffix(".googleads.g.doubleclick.net", "google_ads")
	bl.addSuffix(".pagead2.googlesyndication.com", "google_ads")
	bl.addSuffix(".adservice.google.com", "google_ads")
	bl.addExact("pagead2.googlesyndication.com", "google_ads")
	bl.addExact("googleads.g.doubleclick.net", "google_ads")
	bl.addExact("adservice.google.com", "google_ads")

	// Unity Ads
	bl.addSuffix(".unityads.unity3d.com", "unity_ads")
	bl.addSuffix(".applifier.com", "unity_ads")
	bl.addSuffix(".unity3d.com/ads", "unity_ads")
	bl.addExact("unityads.unity3d.com", "unity_ads")
	bl.addExact("adserver.unityads.unity3d.com", "unity_ads")
	bl.addExact("config.unityads.unity3d.com", "unity_ads")
	bl.addExact("auction.unityads.unity3d.com", "unity_ads")
	bl.addExact("webview.unityads.unity3d.com", "unity_ads")

	// AppLovin
	bl.addSuffix(".applovin.com", "applovin")
	bl.addSuffix(".applvn.com", "applovin")
	bl.addExact("d.applovin.com", "applovin")
	bl.addExact("rt.applovin.com", "applovin")
	bl.addExact("ms.applovin.com", "applovin")

	// Vungle
	bl.addSuffix(".vungle.com", "vungle")
	bl.addExact("api.vungle.com", "vungle")
	bl.addExact("cdn-lb.vungle.com", "vungle")

	// ironSource / Supersonic
	bl.addSuffix(".ironsrc.com", "ironsource")
	bl.addSuffix(".supersonicads.com", "ironsource")
	bl.addSuffix(".is.com", "ironsource")
	bl.addExact("outcome.supersonicads.com", "ironsource")

	// Chartboost
	bl.addSuffix(".chartboost.com", "chartboost")
	bl.addExact("live.chartboost.com", "chartboost")

	// Mopub (Twitter)
	bl.addSuffix(".mopub.com", "mopub")

	// InMobi
	bl.addSuffix(".inmobi.com", "inmobi")

	// AdColony
	bl.addSuffix(".adcolony.com", "adcolony")

	// Tapjoy
	bl.addSuffix(".tapjoy.com", "tapjoy")

	// Fyber / Digital Turbine
	bl.addSuffix(".fyber.com", "fyber")
	bl.addSuffix(".inner-active.com", "fyber")
	bl.addSuffix(".digitalturbine.com", "fyber")

	// Pangle / TikTok Ads
	bl.addSuffix(".pangleglobal.com", "pangle")
	bl.addExact("sf16-mssdk.tiktokcdn.com", "pangle")

	// Yandex Ads
	bl.addSuffix(".yandexadexchange.net", "yandex_ads")

	// StartApp / Start.io
	bl.addSuffix(".startappservice.com", "startapp")
	bl.addSuffix(".startapp.com", "startapp")

	// Generic mobile ad tracking
	bl.addExact("app-measurement.com", "firebase_analytics")
	bl.addSuffix(".app-measurement.com", "firebase_analytics")
	bl.addExact("firebase-settings.crashlytics.com", "firebase_analytics")
	bl.addSuffix(".adjust.com", "adjust_tracking")
	bl.addSuffix(".appsflyer.com", "appsflyer_tracking")
	bl.addSuffix(".branch.io", "branch_tracking")
	bl.addSuffix(".kochava.com", "kochava_tracking")
	bl.addSuffix(".singular.net", "singular_tracking")

	// ── DNS-over-HTTPS (DoH) Providers ──────────────────────────────────
	// Blocking these forces apps to fall back to plain DNS (port 53),
	// which our DnsInterceptor controls.

	bl.addExact("dns.google", "doh_block")
	bl.addExact("dns.google.com", "doh_block")
	bl.addExact("8.8.8.8", "doh_block") // Not a DNS domain but apps may query it
	bl.addExact("8.8.4.4", "doh_block")
	bl.addExact("cloudflare-dns.com", "doh_block")
	bl.addExact("one.one.one.one", "doh_block")
	bl.addExact("1dot1dot1dot1.cloudflare-dns.com", "doh_block")
	bl.addExact("dns.quad9.net", "doh_block")
	bl.addExact("dns9.quad9.net", "doh_block")
	bl.addExact("dns.nextdns.io", "doh_block")
	bl.addExact("doh.opendns.com", "doh_block")
	bl.addExact("dns.adguard.com", "doh_block")
	bl.addExact("dns.adguard-dns.com", "doh_block")
	bl.addExact("doh.cleanbrowsing.org", "doh_block")
	bl.addExact("dns.mullvad.net", "doh_block")
	bl.addExact("freedns.controld.com", "doh_block")
	bl.addExact("dns.controld.com", "doh_block")
	bl.addExact("doh.dns.apple.com", "doh_block")
	bl.addExact("mask.icloud.com", "doh_block")     // iCloud Private Relay
	bl.addExact("mask-h2.icloud.com", "doh_block")   // iCloud Private Relay

	count := len(bl.exactDomains) + len(bl.suffixes)
	logf("Native blocklist loaded: %d exact + %d suffix rules", len(bl.exactDomains), len(bl.suffixes))
	_ = count
}

func (bl *nativeBlocklist) addExact(domain, reason string) {
	bl.exactDomains[strings.ToLower(domain)] = reason
}

func (bl *nativeBlocklist) addSuffix(suffix, reason string) {
	bl.suffixes = append(bl.suffixes, suffixRule{
		suffix: strings.ToLower(suffix),
		reason: reason,
	})
}
