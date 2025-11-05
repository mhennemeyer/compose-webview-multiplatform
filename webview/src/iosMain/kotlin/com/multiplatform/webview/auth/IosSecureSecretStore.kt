@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class, kotlinx.cinterop.BetaInteropApi::class)
package com.multiplatform.webview.auth

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value
import keychainshim.KCAddGenericPassword
import keychainshim.KCCopyGenericPassword
import keychainshim.KCDeleteGenericPassword
import keychainshim.KCUpdateGenericPassword
import platform.Foundation.NSData
import platform.Foundation.create
import platform.LocalAuthentication.LAContext
import platform.Security.*

// iOS SecureSecretStore backed by Keychain + SecAccessControl (UserPresence)
// Policy: require user presence (biometrics or device passcode) per access.
// Storage class: kSecClassGenericPassword with service-scoped entries.
actual class SecretStoreConfig

actual fun secureSecretStore(ctx: BiometricContext, config: SecretStoreConfig): SecureSecretStore =
    IosSecureSecretStore()

private class IosSecureSecretStore : SecureSecretStore {
    private val service = "com.multiplatform.webview.auth"

    override suspend fun save(name: String, data: ByteArray, reason: String?): Boolean {
        val ctx = LAContext()
        val access = createAccessControl() ?: return false
        val valueData = data.toNSData()

        val status = KCAddGenericPassword(
            service,
            name,
            valueData,
            ctx,
            access,
            reason
        )
        return when (status) {
            errSecSuccess -> true
            errSecDuplicateItem -> {
                val st = KCUpdateGenericPassword(
                    service,
                    name,
                    valueData,
                    ctx,
                    reason
                )
                st == errSecSuccess
            }
            else -> false
        }
    }

    override suspend fun read(name: String, reason: String?): ByteArray? {
        val ctx = LAContext()
        memScoped {
            val outStatus = alloc<IntVar>()
            val data: NSData? = KCCopyGenericPassword(
                service,
                name,
                ctx,
                reason,
                outStatus.ptr
            )
            return when (outStatus.value) {
                errSecSuccess -> data?.toByteArray()
                errSecItemNotFound -> null
                errSecUserCanceled, errSecAuthFailed, errSecInteractionNotAllowed -> null
                else -> null
            }
        }
    }

    override suspend fun delete(name: String): Boolean {
        val status = KCDeleteGenericPassword(
            service,
            name
        )
        return status == errSecSuccess || status == errSecItemNotFound
    }

    private fun createAccessControl(): SecAccessControlRef? {
        // Require user presence; item is available only when a passcode is set and stays on this device.
        val accessible = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        val flags = kSecAccessControlUserPresence
        // Pass null error for simplicity; we can surface errors later if needed.
        return SecAccessControlCreateWithFlags(null, accessible, flags, null)
    }
}

private fun ByteArray.toNSData(): NSData = usePinned { pinned ->
    NSData.create(bytes = pinned.addressOf(0), length = this.size.convert())
}

private fun NSData.toByteArray(): ByteArray {
    val length = this.length.toInt()
    val bytes = ByteArray(length)
    bytes.usePinned { pinned ->
        platform.posix.memcpy(pinned.addressOf(0), this.bytes, this.length)
    }
    return bytes
}
