package app.pwhs.blockads.service

import android.os.ParcelFileDescriptor
import app.pwhs.blockads.data.dao.DnsLogDao
import app.pwhs.blockads.data.entities.DnsLogEntry
import app.pwhs.blockads.data.repository.FilterListRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import timber.log.Timber
import tunnel.DomainChecker
import tunnel.LogCallback
import tunnel.SocketProtector

/**
 * Bridge between Android VpnService and the Go DNS tunnel engine.
 *
 * Responsibilities:
 * - Pass TUN file descriptor to Go engine
 * - Implement [DomainChecker] so Go calls Kotlin's mmap'd Trie for blocking decisions
 * - Implement [SocketProtector] so Go can protect sockets from VPN routing loop
 * - Receive DNS log events from Go and write to Room DB
 */
class GoTunnelAdapter(
    private val vpnService: AdBlockVpnService,
    private val filterRepo: FilterListRepository,
    private val dnsLogDao: DnsLogDao,
    private val scope: CoroutineScope,
) {
    private val engine = tunnel.Tunnel.newEngine()

    @Volatile
    private var isRunning = false

    /**
     * Configure the DNS settings for the Go engine.
     */
    fun configureDns(
        protocol: String,
        primary: String,
        fallback: String,
        dohUrl: String,
    ) {
        engine.setDNS(protocol, primary, fallback, dohUrl)
    }

    /**
     * Configure the block response type.
     * @param responseType "CUSTOM_IP", "NXDOMAIN", or "REFUSED"
     */
    fun setBlockResponseType(responseType: String) {
        engine.setBlockResponseType(responseType)
    }

    /**
     * Configure SafeSearch and YouTube restricted mode.
     */
    fun configureSafeSearch(safeSearchEnabled: Boolean, youtubeRestricted: Boolean) {
        engine.setSafeSearch(safeSearchEnabled)
        engine.setYouTubeRestricted(youtubeRestricted)
    }

    /**
     * Set up the domain checker (uses Kotlin's FilterListRepository).
     */
    private fun setupDomainChecker() {
        engine.setDomainChecker(object : DomainChecker {
            override fun isBlocked(domain: String): Boolean {
                return filterRepo.isBlocked(domain)
            }

            override fun getBlockReason(domain: String): String {
                return filterRepo.getBlockReason(domain)
            }
        })
    }

    /**
     * Set the DNS log callback.
     */
    private fun setupLogCallback() {
        engine.setLogCallback(object : LogCallback {
            override fun onDNSQuery(
                domain: String,
                blocked: Boolean,
                queryType: Long,
                responseTimeMs: Long,
                appName: String,
                resolvedIP: String,
                blockedBy: String,
            ) {
                scope.launch(Dispatchers.IO) {
                    try {
                        val entry = DnsLogEntry(
                            domain = domain,
                            isBlocked = blocked,
                            queryType = dnsQueryTypeToString(queryType.toInt()),
                            responseTimeMs = responseTimeMs,
                            appName = appName,
                            resolvedIp = resolvedIP,
                            blockedBy = blockedBy,
                            timestamp = System.currentTimeMillis(),
                        )
                        dnsLogDao.insert(entry)
                    } catch (e: Exception) {
                        Timber.e(e, "Error logging DNS query for $domain")
                    }
                }
            }
        })
    }

    /**
     * Start the Go tunnel engine.
     * This method blocks the calling thread until [stop] is called.
     *
     * @param vpnInterface The TUN file descriptor from VpnService
     */
    fun start(vpnInterface: ParcelFileDescriptor) {
        if (isRunning) return
        isRunning = true

        setupDomainChecker()
        setupLogCallback()

        val fd = vpnInterface.fd
        Timber.d("Starting Go tunnel engine with fd=$fd")

        // Create socket protector that delegates to VpnService.protect()
        val protector = SocketProtector { fd ->
            try {
                vpnService.protectSocket(fd.toInt())
            } catch (e: Exception) {
                Timber.e(e, "Failed to protect socket fd=$fd")
                false
            }
        }

        // Start the Go engine (this blocks the thread)
        engine.start(fd.toLong(), protector)
    }

    /**
     * Stop the Go tunnel engine.
     */
    fun stop() {
        isRunning = false
        engine.stop()
        Timber.d("Go tunnel engine stopped")
    }

    /**
     * Get engine statistics as JSON.
     */
    fun getStats(): String {
        return engine.stats
    }

    companion object {
        /**
         * Convert DNS query type number to human-readable string.
         * DNS types defined in RFC 1035 & 3596.
         */
        private fun dnsQueryTypeToString(type: Int): String = when (type) {
            1 -> "A"
            28 -> "AAAA"
            5 -> "CNAME"
            else -> "OTHER"
        }
    }
}
