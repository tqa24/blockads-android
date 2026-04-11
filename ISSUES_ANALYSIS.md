# BlockAds Open Issues Analysis (2026-04-11)

Total: **28 open issues**

---

## PRIORITY 1: BUGS - Fix Now

These are core functionality bugs affecting many users. Should be fixed in the next release.

| # | Title | Why Fix Now | Estimated Effort |
|---|-------|-------------|------------------|
| **#126** | Custom Lists 'Statistics' shows 0 | Core feature broken - custom lists appear non-functional to users. Likely a counting bug in `StatisticsViewModel.kt` that only counts default lists. | Small |
| **#125** | Unable to add custom filter lists (oisd, etc.) | Blocks users from adding popular filter lists. Likely a URL validation or parsing issue in `CustomFilterManager.kt` or `FilterListRepository.kt`. | Small |
| **#124** | Whitelist domain not working instantly | Whitelist changes don't apply until reboot. Need to flush DNS cache or trigger service reload after whitelist update. | Small-Medium |
| **#56** | Whitelist filter lists improperly load | Shows wrong rule count from whitelist files. Parsing issue - other apps (AdGuard, DNSNet) read the same lists correctly. | Small |

---

## PRIORITY 2: BUGS - Fix Soon

Important but either complex to fix or affect fewer users.

| # | Title | Notes | Estimated Effort |
|---|-------|-------|------------------|
| **#130** | Root Proxy mode doesn't work | Root mode completely broken while VPN works. Involves `RootProxyService.kt` + `IptablesManager.kt`. Needs deep debugging. | Large |
| **#129** | Internal domains not accessible in WireGuard mode | Private DNS (e.g., 10.8.0.1) not resolving through BlockAds WireGuard. Need to forward internal domain queries to WireGuard DNS. | Medium |
| **#106** | Brave Browser + BlockAds broken | Sites don't fully load in Brave since v5.x. Brave may use its own DNS (DoH). May need per-browser handling or documentation. | Medium |
| **#63** | Issue with NextDNS | Log discrepancies between app and NextDNS dashboard. 24 comments - active discussion. Custom DNS integration logic issue. | Medium |

---

## PRIORITY 3: FEATURE REQUESTS - Easy to Implement

These FRs have low complexity and existing code infrastructure to build on.

| # | Title | Why Easy | Estimated Effort |
|---|-------|----------|------------------|
| **#120** | Quick Settings toggle | `AdBlockTileService.kt` **already exists**. May just need registration in AndroidManifest or minor fixes. | Tiny |
| **#128** | Automation via intent | `TaskerReceiver.kt` **already exists**. Extend to support enable/disable intents for Tasker/MacroDroid integration. | Small |
| **#69** | Add Delete button for filters | Delete logic exists in `FilterDetailViewModel.kt` and `FilterListRepository.kt`. Just needs a delete button in the Filter list UI. | Small |
| **#92** | Hide app from recent tasks | Single line: `android:excludeFromRecents="true"` in AndroidManifest, or add as a toggle in Settings. | Tiny |
| **#132** | Crowdin/Weblate for translations | Not a code change - project/CI setup. Strings already externalized in `values-*/strings.xml` (20+ languages). | Small (config) |
| **#102** | Watchdog / auto-restart service | `VpnResumeWorker.kt` and `RootProxyResumeWorker.kt` already exist. Extend to monitor service health and auto-restart after updates. | Small |

---

## PRIORITY 4: FEATURE REQUESTS - Medium Effort

Require meaningful new code but are well-scoped.

| # | Title | Notes | Estimated Effort |
|---|-------|-------|------------------|
| **#91** | WireGuard blocks local servers | Need to exclude LAN/private IP ranges (10.x, 192.168.x, 172.16-31.x) from WireGuard tunnel. Config change in `WireGuardConfigParser.kt`. | Medium |
| **#104** | Accessing by IP address blocked | IP addresses shouldn't go through domain filtering. Need to detect and bypass IPs in DNS resolution. | Medium |
| **#123** | Root Proxy conflicts with other VPNs | Root proxy should work independently of VPN slot. AdGuard handles this - study their approach. Related to #130. | Medium |
| **#105** | Root Mode without VPN | Duplicate of #123/#130 theme. Users want root-based ad blocking without consuming VPN slot. | Medium |
| **#107** | Per-app domain blocking/unblocking | `FirewallRule.kt` and `FirewallManager.kt` exist. Need to extend domain rules to be per-app scoped. | Medium-Large |
| **#118** | Intercept hardcoded port 53 traffic | Redirect all port 53 traffic through BlockAds even if apps hardcode DNS IPs (e.g., 8.8.8.8). Needs iptables rules. | Medium |

---

## PRIORITY 5: FEATURE REQUESTS - Large Effort / Long-term

Major features requiring significant development.

| # | Title | Notes | Estimated Effort |
|---|-------|-------|------------------|
| **#133** | DNS over HTTP/3 and QUIC | New protocol implementation. Requires QUIC library integration. | Large |
| **#119** | Shizuku/ADB connection mode | New connection mode alongside VPN and Root. Requires Shizuku API integration. | Large |
| **#89** | Bypass DPI / spoof SNI RST | Deep packet inspection bypass. Would need integration with byedpi or similar library. | Large |
| **#74** | Block internet by default for new apps | Firewall functionality - need to monitor app installs and apply default-deny rules. `FirewallManager.kt` exists as base. | Large |
| **#73** | Queries tab, App tab, Stats, Profiles | Major UI restructuring with new tabs and per-app management. | Very Large |
| **#111** | Filter building locally and VPS | Build filter lists on-device or user's VPS instead of downloading. Novel architecture. | Very Large |
| **#100** | CA Certificate for HTTPS filtering | `HttpsFilteringScreen.kt` exists but full CA cert generation and installation flow is complex. | Large |
| **#95** | Multiple requests (DPI bypass, custom DNS, nav bar, etc.) | Umbrella issue - individual items vary in effort. | Mixed |

---

## Recommended Action Plan

### Next Release (Quick Wins)
1. **#126** - Fix custom list statistics counter
2. **#125** - Fix custom filter list URL validation/parsing
3. **#124** - Apply whitelist changes without reboot
4. **#56** - Fix whitelist filter list parsing
5. **#120** - Verify Quick Settings tile works (code exists)
6. **#69** - Add delete button to filter list UI
7. **#92** - Add hide-from-recents option

### Release After
1. **#128** - Extend Tasker/intent automation
2. **#102** - Watchdog auto-restart
3. **#132** - Set up Crowdin for translations
4. **#91** - Exclude LAN from WireGuard
5. **#130** - Debug and fix Root Proxy mode

### Backlog
- #129, #106, #63 (compatibility bugs - need investigation)
- #107, #118, #104, #123, #105 (medium FRs)
- #133, #119, #89, #74, #73, #111, #100, #95 (long-term FRs)

---

## Summary Stats

| Category | Count |
|----------|-------|
| Bugs - Fix Now | 4 |
| Bugs - Fix Soon | 4 |
| FR - Easy | 6 |
| FR - Medium | 6 |
| FR - Large/Long-term | 8 |
| **Total** | **28** |
