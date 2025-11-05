package com.multiplatform.webview.auth

/**
 * Secure secret store abstraction. Implementations should protect secrets via
 * platform hardware-backed facilities (Android Keystore / iOS Keychain) and gate
 * access by biometrics or device credential.
 */
interface SecureSecretStore {
    /** Save or overwrite a named secret (e.g., token). Returns true on success. */
    suspend fun save(name: String, data: ByteArray, reason: String? = null): Boolean

    /** Read a named secret. Returns null if missing or user cancels/denied. */
    suspend fun read(name: String, reason: String? = null): ByteArray?

    /** Delete a named secret, returns true if removed or didn’t exist. */
    suspend fun delete(name: String): Boolean
}

// Expect a factory per platform with optional policy knobs.
expect class SecretStoreConfig()

expect fun secureSecretStore(ctx: BiometricContext, config: SecretStoreConfig = SecretStoreConfig()): SecureSecretStore
