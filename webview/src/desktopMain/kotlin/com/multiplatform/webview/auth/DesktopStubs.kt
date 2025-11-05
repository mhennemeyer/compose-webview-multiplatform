package com.multiplatform.webview.auth

// Desktop stubs: biometrics not available; store is non-secure in-memory.

actual class BiometricContext internal constructor()

actual fun biometricAuth(ctx: BiometricContext): BiometricAuth = object : BiometricAuth {
    override fun capabilities(): BiometricCapabilities = BiometricCapabilities(
        status = BiometricStatus.NoHardware,
        supportsDeviceCredentialFallback = false
    )

    override suspend fun authenticate(reason: String, allowDeviceCredentialFallback: Boolean): BiometricResult =
        BiometricResult.Error(BiometricErrorCode.NotAvailable, "Biometrics not available on desktop")
}

actual class SecretStoreConfig

actual fun secureSecretStore(ctx: BiometricContext, config: SecretStoreConfig): SecureSecretStore =
    InMemorySecretStore()

private class InMemorySecretStore : SecureSecretStore {
    private val map = mutableMapOf<String, ByteArray>()
    override suspend fun save(name: String, data: ByteArray, reason: String?): Boolean {
        map[name] = data.copyOf()
        return true
    }
    override suspend fun read(name: String, reason: String?): ByteArray? = map[name]?.copyOf()
    override suspend fun delete(name: String): Boolean { map.remove(name); return true }
}
