package com.multiplatform.webview.auth

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.suspendCancellableCoroutine
import platform.Foundation.NSError
import platform.LocalAuthentication.*
import kotlin.coroutines.resume

actual class BiometricContext internal constructor()

// Convenience factory for iOS to construct a BiometricContext
fun biometricContextOf(): BiometricContext = BiometricContext()

actual fun biometricAuth(ctx: BiometricContext): BiometricAuth = IosBiometricAuth()

@OptIn(ExperimentalForeignApi::class)
private class IosBiometricAuth : BiometricAuth {
    override fun capabilities(): BiometricCapabilities {
        val ctx = LAContext()
        val canBio = ctx.canEvaluatePolicy(LAPolicyDeviceOwnerAuthenticationWithBiometrics, null)
        val canAny = ctx.canEvaluatePolicy(LAPolicyDeviceOwnerAuthentication, null)
        return when {
            canBio -> BiometricCapabilities(BiometricStatus.Available, supportsDeviceCredentialFallback = canAny)
            canAny -> BiometricCapabilities(BiometricStatus.Available, supportsDeviceCredentialFallback = true)
            else -> BiometricCapabilities(BiometricStatus.NotEnrolled, supportsDeviceCredentialFallback = false)
        }
    }

    override suspend fun authenticate(
        reason: String,
        allowDeviceCredentialFallback: Boolean
    ): BiometricResult = suspendCancellableCoroutine { cont ->
        val ctx = LAContext()
        val policy = if (allowDeviceCredentialFallback) LAPolicyDeviceOwnerAuthentication
        else LAPolicyDeviceOwnerAuthenticationWithBiometrics
        ctx.evaluatePolicy(policy, localizedReason = reason) { success: Boolean, error: NSError? ->
            if (success) {
                if (cont.isActive) cont.resume(BiometricResult.Success)
            } else {
                val code = when (error?.code) {
                    LAErrorSystemCancel, LAErrorAppCancel, LAErrorUserCancel -> BiometricErrorCode.Canceled
                    LAErrorBiometryNotAvailable -> BiometricErrorCode.NotAvailable
                    LAErrorBiometryNotEnrolled -> BiometricErrorCode.NotEnrolled
                    LAErrorBiometryLockout -> BiometricErrorCode.Lockout
                    else -> BiometricErrorCode.Unknown
                }
                if (cont.isActive) cont.resume(BiometricResult.Error(code, error?.localizedDescription))
            }
        }
        cont.invokeOnCancellation { ctx.invalidate() }
    }
}
