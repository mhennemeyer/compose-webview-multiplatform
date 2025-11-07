package com.kevinnzou.sample

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.Button
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.multiplatform.webview.auth.BiometricResult
import com.multiplatform.webview.auth.biometricAuth
import com.multiplatform.webview.auth.biometricContextOf
import com.multiplatform.webview.auth.secureSecretStore
import kotlinx.coroutines.launch

@Composable
actual fun BiometricsPlatformContent() {
    val scope = rememberCoroutineScope()
    val statusText = remember { mutableStateOf("Ready") }

    val bio = biometricAuth(biometricContextOf())
    val store = secureSecretStore(biometricContextOf())

    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("Status: ${statusText.value}")
        Button(onClick = {
            val caps = bio.capabilities()
            statusText.value = "Capabilities: $caps"
        }) { Text("Check capabilities") }

        Button(onClick = {
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
            scope.launch {
                val ok = store.save("demo-token", "very-secret".encodeToByteArray(), reason = "Save token")
                statusText.value = if (ok) "Saved secret" else "Save failed"
            }
        }) { Text("Save secret") }

        Button(onClick = {
            scope.launch {
                val data = store.read("demo-token", reason = "Read token")
                statusText.value = if (data != null) "Read: ${data.decodeToString()}" else "Read: null"
            }
        }) { Text("Read secret") }

        Button(onClick = {
            scope.launch {
                // Reset status to initial state after delete, regardless of outcome
                store.delete("demo-token")
                statusText.value = "Ready"
            }
        }) { Text("Delete secret") }
    }
}
