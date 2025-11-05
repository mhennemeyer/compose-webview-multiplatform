package com.multiplatform.webview.auth

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.util.Log
import androidx.fragment.app.FragmentActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

// Android SecretStoreConfig – optional future knobs
actual class SecretStoreConfig

actual fun secureSecretStore(ctx: BiometricContext, config: SecretStoreConfig): SecureSecretStore =
    AndroidSecureSecretStore(ctx.activity)

private class AndroidSecureSecretStore(private val activity: FragmentActivity) : SecureSecretStore {
    private val alias = "com.multiplatform.webview.auth.SECRET_KEY"
    private val prefs: SharedPreferences by lazy {
        activity.getSharedPreferences("biometric_store", Context.MODE_PRIVATE)
    }

    override suspend fun save(name: String, data: ByteArray, reason: String?): Boolean {
        // First try: authenticate with CryptoObject bound to Cipher (preferred)
        var cipher = authenticateCipher(Cipher.ENCRYPT_MODE, reason ?: "Authenticate to save secret")
        if (cipher == null) {
            // Fallback: do a plain biometric/device-credential auth, then rely on keystore auth parameters
            // (grace window) to allow Cipher use without CryptoObject.
            val bio = biometricAuth(biometricContextOf(activity))
            when (val res = bio.authenticate(reason ?: "Authenticate to save secret")) {
                is BiometricResult.Success -> {
                    // After successful auth, create a fresh cipher and proceed.
                    try { cipher = createCipher(Cipher.ENCRYPT_MODE) } catch (_: Throwable) { return false }
                }
                is BiometricResult.Error -> return false
            }
        }
        var cipherText: ByteArray
        var iv: ByteArray
        try {
            cipherText = cipher!!.doFinal(data)
            iv = cipher!!.iv
        } catch (_: Throwable) {
            // Possible cause: existing key was created without a grace window and requires
            // per-use CryptoObject auth. Regenerate the key with current parameters and retry once.
            try {
                deleteKey()
                ensureKey()
                val c2 = createCipher(Cipher.ENCRYPT_MODE)
                cipherText = c2.doFinal(data)
                iv = c2.iv
            } catch (_: Throwable) {
                return false
            }
        }
        prefs.edit()
            .putString("${name}_iv", iv.encodeBase64())
            .putString("${name}_ct", cipherText.encodeBase64())
            .apply()
        return true
    }

    override suspend fun read(name: String, reason: String?): ByteArray? {
        val ivB64 = prefs.getString("${name}_iv", null) ?: return null
        val ctB64 = prefs.getString("${name}_ct", null) ?: return null

        val iv = ivB64.decodeBase64() ?: return null
        val ct = ctB64.decodeBase64() ?: return null

        // First try: authenticate with CryptoObject bound to Cipher (preferred)
        var cipher = authenticateCipher(Cipher.DECRYPT_MODE, reason ?: "Authenticate to view secret", iv)
        if (cipher == null) {
            // Fallback: do a plain biometric/device-credential auth, then rely on keystore auth parameters
            // (grace window) to allow Cipher use without CryptoObject.
            val bio = biometricAuth(biometricContextOf(activity))
            when (val res = bio.authenticate(reason ?: "Authenticate to view secret")) {
                is BiometricResult.Success -> {
                    try { cipher = createCipher(Cipher.DECRYPT_MODE, iv) } catch (_: Throwable) { return null }
                }
                is BiometricResult.Error -> return null
            }
        }
        return try {
            cipher!!.doFinal(ct)
        } catch (_: Throwable) {
            null
        }
    }

    override suspend fun delete(name: String): Boolean {
        prefs.edit().remove("${name}_iv").remove("${name}_ct").apply()
        return true
    }

    private fun createCipher(mode: Int, iv: ByteArray? = null): Cipher {
        ensureKey()
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        var secretKey = keyStore.getKey(alias, null) as SecretKey
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        try {
            if (mode == Cipher.ENCRYPT_MODE) {
                cipher.init(mode, secretKey)
            } else {
                val spec = GCMParameterSpec(128, iv)
                cipher.init(mode, secretKey, spec)
            }
        } catch (e: android.security.keystore.KeyPermanentlyInvalidatedException) {
            // The key was invalidated (e.g., new biometric enrolled). Regenerate and retry once.
            deleteKey()
            ensureKey()
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            secretKey = ks.getKey(alias, null) as SecretKey
            if (mode == Cipher.ENCRYPT_MODE) {
                cipher.init(mode, secretKey)
            } else {
                val spec = GCMParameterSpec(128, iv)
                cipher.init(mode, secretKey, spec)
            }
        }
        return cipher
    }

    private fun ensureKey() {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val exists = keyStore.containsAlias(alias)
        if (!exists) {
            val keyGenerator = KeyGenerator.getInstance("AES", "AndroidKeyStore")
            val builder = android.security.keystore.KeyGenParameterSpec.Builder(
                alias,
                android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or
                        android.security.keystore.KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(android.security.keystore.KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(android.security.keystore.KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                // Choose authenticator class based on availability: if no biometrics, use device credential only.
                val mgr = BiometricManager.from(activity)
                val bioOnly = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.BIOMETRIC_WEAK
                val authClass = if (mgr.canAuthenticate(bioOnly) == BiometricManager.BIOMETRIC_SUCCESS) {
                    android.security.keystore.KeyProperties.AUTH_BIOMETRIC_STRONG or android.security.keystore.KeyProperties.AUTH_DEVICE_CREDENTIAL
                } else {
                    android.security.keystore.KeyProperties.AUTH_DEVICE_CREDENTIAL
                }
                // Use a short grace period to allow a session-auth fallback; still requires recent user auth.
                builder.setUserAuthenticationParameters(
                    30, // seconds
                    authClass
                )
            } else {
                // On older APIs, we can only set validity duration seconds (>0). Use 5s grace.
                @Suppress("DEPRECATION")
                builder.setUserAuthenticationValidityDurationSeconds(5)
            }

            keyGenerator.init(builder.build())
            keyGenerator.generateKey()
        }
    }

    private fun deleteKey() {
        runCatching {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }
        }
    }

    private fun allowedAuthenticators(): Int {
        val B = BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.BIOMETRIC_WEAK
        val DC = BiometricManager.Authenticators.DEVICE_CREDENTIAL
        return B or DC
    }

    private suspend fun authenticateCipher(mode: Int, reason: String, iv: ByteArray? = null): Cipher? =
        kotlinx.coroutines.suspendCancellableCoroutine { cont ->
            // If no biometrics are enrolled/available, skip CryptoObject path and fall back to
            // plain authenticate (DEVICE_CREDENTIAL) + keystore grace window.
            val mgr = BiometricManager.from(activity)
            val bioOnly = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.BIOMETRIC_WEAK
            if (mgr.canAuthenticate(bioOnly) != BiometricManager.BIOMETRIC_SUCCESS) {
                cont.resume(null, null)
                return@suspendCancellableCoroutine
            }

            val cipher = try {
                createCipher(mode, iv)
            } catch (_: Throwable) {
                cont.resume(null, null)
                return@suspendCancellableCoroutine
            }
            val executor = ContextCompat.getMainExecutor(activity)
            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val c = result.cryptoObject?.cipher
                    if (cont.isActive) cont.resume(c, null)
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (cont.isActive) cont.resume(null, null)
                }
                override fun onAuthenticationFailed() {
                    // transient; keep prompt open
                }
            }
            val prompt = BiometricPrompt(activity, executor, callback)
            val builder = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Authenticate")
                .setSubtitle(reason)

            // When using a CryptoObject, restrict to biometrics-only on all API levels.
            // Some devices/OEM builds suppress the sheet if DEVICE_CREDENTIAL is combined
            // with a CryptoObject. We handle device credential via a plain-auth fallback
            // and a short keystore auth grace window instead.
            builder.setAllowedAuthenticators(bioOnly)
            builder.setNegativeButtonText("Cancel")

            val info = builder.build()
            try {
                prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
            } catch (_: Throwable) {
                if (cont.isActive) cont.resume(null, null)
            }
            cont.invokeOnCancellation {
                // No explicit cancel API required; prompt dismisses when activity finishes.
            }
        }
}

private fun ByteArray.encodeBase64(): String = android.util.Base64.encodeToString(this, android.util.Base64.NO_WRAP)
private fun String.decodeBase64(): ByteArray? = try {
    android.util.Base64.decode(this, android.util.Base64.NO_WRAP)
} catch (_: Throwable) { null }
