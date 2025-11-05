package com.kevinnzou.sample

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBars
import androidx.compose.material.Icon
import androidx.compose.material.IconButton
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Scaffold
import androidx.compose.material.Text
import androidx.compose.material.TopAppBar
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.navigation.NavHostController

/**
 * Biometrics sample entry screen. Platform-specific content is provided
 * by [BiometricsPlatformContent].
 */
@Composable
internal fun BiometricsSample(navHostController: NavHostController? = null) {
    MaterialTheme {
        Scaffold { innerPadding ->
            Column(
                modifier =
                    Modifier
                        .padding(innerPadding)
                        .fillMaxSize(),
            ) {
                TopAppBar(
                    modifier =
                        Modifier
                            .background(
                                color = MaterialTheme.colors.primary,
                            ).padding(
                                top =
                                    WindowInsets.statusBars
                                        .asPaddingValues()
                                        .calculateTopPadding(),
                            ),
                    title = { Text(text = "Biometrics Sample") },
                    navigationIcon = {
                        IconButton(onClick = { navHostController?.popBackStack() }) {
                            Icon(
                                imageVector = Icons.Default.ArrowBack,
                                contentDescription = "Back",
                            )
                        }
                    },
                )

                BiometricsPlatformContent()
            }
        }
    }
}

@Composable
expect fun BiometricsPlatformContent()
