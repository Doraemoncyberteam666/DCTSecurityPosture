package com.dct.securityposture.security

import android.content.Context
import com.google.android.gms.tasks.Task
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenResponse
import com.google.android.play.core.integrity.IntegrityTokenRequest

object PlayIntegrity {
    /**
     * Real Play Integrity flow:
     * 1. Backend creates a cryptographically random nonce for the session/action.
     * 2. App requests an integrity token using that nonce.
     * 3. App sends token to backend.
     * 4. Backend calls Google Play Developer API to decode/verify verdict.
     *
     * Never trust a verdict decoded only on-device.
     */
    fun requestToken(context: Context, nonceFromServer: String): Task<IntegrityTokenResponse> {
        val manager = IntegrityManagerFactory.create(context)
        val request = IntegrityTokenRequest.builder()
            .setNonce(nonceFromServer)
            .build()
        return manager.requestIntegrityToken(request)
    }
}
