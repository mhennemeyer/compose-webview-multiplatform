package com.multiplatform.webview

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import com.multiplatform.webview.auth.BiometricResult
import com.multiplatform.webview.auth.biometricAuth
import com.multiplatform.webview.auth.biometricContextOf
import com.multiplatform.webview.auth.secureSecretStore
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.launch

/**
 * Lightweight host activity that provides a FragmentActivity context for BiometricPrompt
 * while keeping the main sample entry activity as a ComponentActivity.
 *
 * Callers start this Activity with an extra "action" specifying one of:
 *  - "capabilities"
 *  - "authenticate"
 *  - "save" (requires extras: name:String, data:ByteArray)
 *  - "read" (requires extras: name:String)
 *  - "delete" (requires extras: name:String)
 *
 * Results are returned via setResult(RESULT_OK) with extras:
 *  - success:Boolean
 *  - message:String (optional)
 *  - bytes:ByteArray (for read)
 */
class BiometricHostActivity : AppCompatActivity() {

    private val scope = MainScope()
    private var handled = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Defer handling until Activity is RESUMED to ensure BiometricPrompt can show reliably.
    }

    override fun onResume() {
        super.onResume()
        if (!handled) {
            handled = true
            // Post to the next main loop to ensure the window is fully resumed and drawn
            Handler(Looper.getMainLooper()).post { handle() }
        }
    }

    private fun handle() {
        val action = intent.getStringExtra(EXTRA_ACTION)
        val bio = biometricAuth(biometricContextOf(this))
        val store = secureSecretStore(biometricContextOf(this))

        // Ensure we invoke any BiometricPrompt.authenticate only when the Activity is RESUMED.
        scope.launch {
            when (action) {
                ACTION_CAPABILITIES -> {
                    val caps = bio.capabilities()
                    finishOk(success = true, message = caps.toString())
                }
                ACTION_AUTHENTICATE -> {
                    when (val res = bio.authenticate("Authenticate")) {
                        is BiometricResult.Success -> finishOk(true, "success")
                        is BiometricResult.Error -> finishOk(false, "${res.code}: ${res.message ?: ""}")
                    }
                }
                ACTION_SAVE -> {
                    val name = intent.getStringExtra(EXTRA_NAME)
                    val data = intent.getByteArrayExtra(EXTRA_DATA)
                    val ok = if (name != null && data != null) store.save(name, data, "Save secret") else false
                    finishOk(ok, if (ok) "saved" else "save failed")
                }
                ACTION_READ -> {
                    val name = intent.getStringExtra(EXTRA_NAME)
                    val bytes = if (name != null) store.read(name, "Read secret") else null
                    if (bytes != null) finishOk(true, "read", bytes) else finishOk(false, "read: null")
                }
                ACTION_DELETE -> {
                    val name = intent.getStringExtra(EXTRA_NAME)
                    val ok = if (name != null) store.delete(name) else false
                    finishOk(ok, if (ok) "deleted" else "delete failed")
                }
                else -> finishOk(false, "unknown action")
            }
        }
    }

    private fun finishOk(success: Boolean, message: String? = null, bytes: ByteArray? = null) {
        val data = Intent().apply {
            putExtra(EXTRA_SUCCESS, success)
            if (message != null) putExtra(EXTRA_MESSAGE, message)
            if (bytes != null) putExtra(EXTRA_BYTES, bytes)
        }
        setResult(Activity.RESULT_OK, data)
        finish()
    }

    companion object {
        const val EXTRA_ACTION = "action"
        const val EXTRA_NAME = "name"
        const val EXTRA_DATA = "data"

        const val EXTRA_SUCCESS = "success"
        const val EXTRA_MESSAGE = "message"
        const val EXTRA_BYTES = "bytes"

        const val ACTION_CAPABILITIES = "capabilities"
        const val ACTION_AUTHENTICATE = "authenticate"
        const val ACTION_SAVE = "save"
        const val ACTION_READ = "read"
        const val ACTION_DELETE = "delete"
    }
}
