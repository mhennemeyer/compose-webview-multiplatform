package com.multiplatform.webview.auth

import androidx.fragment.app.FragmentActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

actual class BiometricContext internal constructor(val activity: FragmentActivity)

actual fun biometricAuth(ctx: BiometricContext): BiometricAuth = AndroidBiometricAuth(ctx.activity)

private class AndroidBiometricAuth(private val activity: FragmentActivity) : BiometricAuth {

    private fun allowedAuthenticators(allowDeviceCred: Boolean): Int {
        val B = BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.BIOMETRIC_WEAK
        val DC = BiometricManager.Authenticators.DEVICE_CREDENTIAL
        return if (allowDeviceCred) B or DC else B
    }

    override fun capabilities(): BiometricCapabilities {
        val mgr = BiometricManager.from(activity)
        return when (mgr.canAuthenticate(allowedAuthenticators(true))) {
            BiometricManager.BIOMETRIC_SUCCESS -> BiometricCapabilities(BiometricStatus.Available, true)
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> BiometricCapabilities(BiometricStatus.NotEnrolled, true)
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> BiometricCapabilities(BiometricStatus.NoHardware, false)
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> BiometricCapabilities(BiometricStatus.NoHardware, false)
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> BiometricCapabilities(BiometricStatus.Unknown, true)
            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> BiometricCapabilities(BiometricStatus.NoHardware, false)
            BiometricManager.BIOMETRIC_STATUS_UNKNOWN -> BiometricCapabilities(BiometricStatus.Unknown, false)
            else -> BiometricCapabilities(BiometricStatus.Unknown, false)
        }
    }

    override suspend fun authenticate(
        reason: String,
        allowDeviceCredentialFallback: Boolean
    ): BiometricResult = suspendCancellableCoroutine { cont ->
        val executor = ContextCompat.getMainExecutor(activity)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                if (cont.isActive) cont.resume(BiometricResult.Success)
            }
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                val code = when (errorCode) {
                    BiometricPrompt.ERROR_LOCKOUT, BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> BiometricErrorCode.Lockout
                    BiometricPrompt.ERROR_CANCELED, BiometricPrompt.ERROR_USER_CANCELED -> BiometricErrorCode.Canceled
                    BiometricPrompt.ERROR_NO_BIOMETRICS -> BiometricErrorCode.NotEnrolled
                    BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL -> BiometricErrorCode.NotAvailable
                    else -> BiometricErrorCode.Unknown
                }
                if (cont.isActive) cont.resume(BiometricResult.Error(code, errString.toString()))
            }
            override fun onAuthenticationFailed() { /* ignore transient */ }
        }
        val prompt = BiometricPrompt(activity, executor, callback)
        val builder = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authenticate")
            .setSubtitle(reason)
        if (allowDeviceCredentialFallback) {
            builder.setAllowedAuthenticators(allowedAuthenticators(true))
        } else {
            builder.setAllowedAuthenticators(allowedAuthenticators(false))
            builder.setNegativeButtonText("Cancel")
        }
        prompt.authenticate(builder.build())
    }
}

// Factory to build a BiometricContext in Android from a FragmentActivity
fun biometricContextOf(activity: FragmentActivity): BiometricContext = BiometricContext(activity)
