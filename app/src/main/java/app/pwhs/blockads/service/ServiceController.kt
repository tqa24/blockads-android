package app.pwhs.blockads.service

import android.content.Context
import app.pwhs.blockads.data.datastore.AppPreferences
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking

/**
 * Unified service controller that dispatches restart/stop requests
 * to the correct service based on the current routing mode.
 *
 * This avoids the need to check routing mode at every ViewModel callsite.
 */
object ServiceController {

    /**
     * Request a restart of whichever ad-blocking service is currently running.
     * If Root Proxy mode is active, restarts RootProxyService.
     * If VPN mode is active, restarts AdBlockVpnService.
     * Safe to call from any thread.
     */
    fun requestRestart(context: Context) {
        // Check both services — at least one might be running
        if (RootProxyService.isRunning) {
            RootProxyService.requestRestart(context)
        }
        if (AdBlockVpnService.isRunning) {
            AdBlockVpnService.requestRestart(context)
        }
    }
}
