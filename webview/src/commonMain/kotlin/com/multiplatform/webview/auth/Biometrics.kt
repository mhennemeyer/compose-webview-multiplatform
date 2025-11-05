package com.multiplatform.webview.auth

// Shared biometrics API (commonMain)
// Provides a simple, suspend-based abstraction to authenticate the user
// using biometrics and/or device credentials in a multiplatform-friendly way.

enum class BiometricStatus { Available, NotEnrolled, NoHardware, LockedOut, Unknown }

data class BiometricCapabilities(
    val status: BiometricStatus,
    val supportsDeviceCredentialFallback: Boolean,
)

enum class BiometricErrorCode { Canceled, NotAvailable, NotEnrolled, Lockout, Failed, Unknown }

sealed class BiometricResult {
    data object Success : BiometricResult()
    data class Error(val code: BiometricErrorCode, val message: String? = null) : BiometricResult()
}

interface BiometricAuth {
    fun capabilities(): BiometricCapabilities
    suspend fun authenticate(
        reason: String,
        allowDeviceCredentialFallback: Boolean = true,
    ): BiometricResult
}

// A lightweight context carrier whose actual type is platform-specific.
// - Android actual is ComponentActivity (used by BiometricPrompt)
// - iOS actual is a no-op placeholder (LAContext is created internally)
expect class BiometricContext

expect fun biometricAuth(ctx: BiometricContext): BiometricAuth
