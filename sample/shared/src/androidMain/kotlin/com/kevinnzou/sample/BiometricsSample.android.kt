package com.kevinnzou.sample

import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.Button
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.multiplatform.webview.auth.BiometricResult
import com.multiplatform.webview.auth.biometricAuth
import com.multiplatform.webview.auth.biometricContextOf
import com.multiplatform.webview.auth.secureSecretStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.launch

// Intent protocol constants (duplicated here to avoid depending on the app module class)
private const val EXTRA_ACTION = "action"
private const val EXTRA_NAME = "name"
private const val EXTRA_DATA = "data"

private const val EXTRA_SUCCESS = "success"
private const val EXTRA_MESSAGE = "message"
private const val EXTRA_BYTES = "bytes"

private const val ACTION_CAPABILITIES = "capabilities"
private const val ACTION_AUTHENTICATE = "authenticate"
private const val ACTION_SAVE = "save"
private const val ACTION_READ = "read"
private const val ACTION_DELETE = "delete"

@Composable
actual fun BiometricsPlatformContent() {
    val context = LocalContext.current
    val activity = context as? FragmentActivity
    val scope: CoroutineScope = remember { MainScope() }

    val statusText = remember { mutableStateOf("Ready") }

    if (activity == null) {
        // Use a dedicated AppCompatActivity host for biometrics while keeping MainActivity as ComponentActivity
        val lastAction = remember { mutableStateOf<String?>(null) }
        val launcher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            val data = result.data
            val success = data?.getBooleanExtra(EXTRA_SUCCESS, false) ?: false
            val message = data?.getStringExtra(EXTRA_MESSAGE)
            val bytes = data?.getByteArrayExtra(EXTRA_BYTES)
            val action = lastAction.value
            // Reset status to initial state after delete, regardless of outcome
            if (action == ACTION_DELETE) {
                statusText.value = "Ready"
            } else {
                statusText.value = when {
                    bytes != null -> "Read: ${bytes.decodeToString()}"
                    message != null -> message
                    else -> if (success) "Success" else "Failed"
                }
            }
            lastAction.value = null
        }

        // Debounce clicks to avoid dropped/rapid taps; add immediate feedback
        val lastClickMs = remember { mutableStateOf(0L) }
        fun send(action: String, name: String? = null, payload: ByteArray? = null) {
            val now = SystemClock.elapsedRealtime()
            if (now - lastClickMs.value < 350) {
                Toast.makeText(context, "Please wait…", Toast.LENGTH_SHORT).show()
                return
            }
            lastClickMs.value = now
            Toast.makeText(context, "Click: $action", Toast.LENGTH_SHORT).show()
            // Remember last action so we can reset status on delete
            lastAction.value = action

            val intent = Intent().apply {
                setClassName(context, "com.multiplatform.webview.BiometricHostActivity")
                putExtra(EXTRA_ACTION, action)
                if (name != null) putExtra(EXTRA_NAME, name)
                if (payload != null) putExtra(EXTRA_DATA, payload)
            }
            // Post to main looper to align with host Activity's resumed state expectations
            Handler(Looper.getMainLooper()).post {
                launcher.launch(intent)
            }
        }

        Column(
            modifier = Modifier.fillMaxSize().padding(PaddingValues(16.dp)),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text("Status: ${statusText.value}")
            Button(onClick = { send(ACTION_CAPABILITIES) }) { Text("Check capabilities") }
            Button(onClick = { send(ACTION_AUTHENTICATE) }) { Text("Authenticate") }
            Button(onClick = { send(ACTION_SAVE, name = "demo-token", payload = "very-secret".encodeToByteArray()) }) { Text("Save secret") }
            Button(onClick = { send(ACTION_READ, name = "demo-token") }) { Text("Read secret") }
            Button(onClick = { send(ACTION_DELETE, name = "demo-token") }) { Text("Delete secret") }
        }
        return
    }

    // If we already have a FragmentActivity host, run inline using BiometricPrompt directly
    val bio = biometricAuth(biometricContextOf(activity))
    val store = secureSecretStore(biometricContextOf(activity))

    // Debounce + feedback for inline buttons as well
    val lastInlineClickMs = remember { mutableStateOf(0L) }
    fun preClick(label: String): Boolean {
        val now = SystemClock.elapsedRealtime()
        if (now - lastInlineClickMs.value < 350) {
            Toast.makeText(context, "Please wait…", Toast.LENGTH_SHORT).show()
            return false
        }
        lastInlineClickMs.value = now
        Toast.makeText(context, "Click: $label", Toast.LENGTH_SHORT).show()
        return true
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(PaddingValues(16.dp)),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("Status: ${statusText.value}")
        Button(onClick = {
            if (!preClick("capabilities")) return@Button
            val caps = bio.capabilities()
            statusText.value = "Capabilities: $caps"
        }) { Text("Check capabilities") }

        Button(onClick = {
            if (!preClick("authenticate")) return@Button
            scope.launch {
                when (val res = bio.authenticate("Authenticate to proceed")) {
                    is BiometricResult.Success -> statusText.value = "Auth: success"
                    is BiometricResult.Error -> {
                        val msg = res.message ?: ""
                        statusText.value = "Auth error: ${res.code} $msg"
                    }
                }
            }
        }) { Text("Authenticate") }

        Button(onClick = {
            if (!preClick("save")) return@Button
            scope.launch {
                val ok = store.save("demo-token", "very-secret".encodeToByteArray(), reason = "Save token")
                statusText.value = if (ok) "Saved secret" else "Save failed"
            }
        }) { Text("Save secret") }

        Button(onClick = {
            if (!preClick("read")) return@Button
            scope.launch {
                val data = store.read("demo-token", reason = "Read token")
                statusText.value = if (data != null) "Read: ${data.decodeToString()}" else "Read: null"
            }
        }) { Text("Read secret") }

        Button(onClick = {
            if (!preClick("delete")) return@Button
            scope.launch {
                // Reset status to initial state after delete, regardless of outcome
                store.delete("demo-token")
                statusText.value = "Ready"
            }
        }) { Text("Delete secret") }
    }
}
