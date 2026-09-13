package com.hermes.mobile.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable

private val HermesColors = lightColorScheme()

@Composable
fun HermesTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = HermesColors,
        content = content,
    )
}
