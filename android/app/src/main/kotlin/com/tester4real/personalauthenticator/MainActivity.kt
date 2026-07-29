package com.tester4real.personalauthenticator

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.tester4real.personalauthenticator.vault.VaultSessionManager
import com.tester4real.personalauthenticator.vault.VaultSessionState
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : ComponentActivity() {
    @Inject lateinit var sessionManager: VaultSessionManager
    private val viewModel: VaultGateViewModel by viewModels()
    private var backgroundedAt: Long? = null
    private val screenOffReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == Intent.ACTION_SCREEN_OFF) {
                sessionManager.lock()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            setRecentsScreenshotEnabled(false)
        }
        registerReceiver(screenOffReceiver, IntentFilter(Intent.ACTION_SCREEN_OFF))
        setContent {
            MaterialTheme {
                val state by viewModel.uiState.collectAsStateWithLifecycle()
                VaultGate(
                    state = state,
                    onSetup = viewModel::setup,
                    onUnlock = viewModel::unlock,
                    onLock = viewModel::lock,
                )
            }
        }
    }

    override fun onStart() {
        super.onStart()
        val since = backgroundedAt
        backgroundedAt = null
        if (since != null &&
            SystemClock.elapsedRealtime() - since >= BACKGROUND_LOCK_MILLIS
        ) {
            sessionManager.lock()
        }
    }

    override fun onStop() {
        backgroundedAt = SystemClock.elapsedRealtime()
        super.onStop()
    }

    override fun onDestroy() {
        unregisterReceiver(screenOffReceiver)
        super.onDestroy()
    }

    companion object {
        private const val BACKGROUND_LOCK_MILLIS = 30_000L
    }
}

@Composable
private fun VaultGate(
    state: VaultGateUiState,
    onSetup: (String, String) -> Unit,
    onUnlock: (String) -> Unit,
    onLock: () -> Unit,
) {
    Surface(modifier = Modifier.fillMaxSize()) {
        when (state.session) {
            VaultSessionState.NeedsSetup ->
                PinSetupScreen(state, onSetup)
            VaultSessionState.Locked ->
                PinUnlockScreen(state, onUnlock)
            VaultSessionState.Unlocked ->
                UnlockedScreen(onLock)
        }
    }
}

@Composable
private fun PinSetupScreen(
    state: VaultGateUiState,
    onSetup: (String, String) -> Unit,
) {
    var pin by remember { mutableStateOf("") }
    var confirmation by remember { mutableStateOf("") }
    GateColumn(
        title = "Create your PIN",
        description = "Use 4–8 digits. This PIN is separate from your sync password.",
        error = state.error,
    ) {
        PinField("PIN", pin) { pin = it }
        PinField("Confirm PIN", confirmation) { confirmation = it }
        Button(
            onClick = {
                onSetup(pin, confirmation)
                pin = ""
                confirmation = ""
            },
            enabled = !state.busy,
            modifier = Modifier.fillMaxWidth(),
        ) {
            if (state.busy) CircularProgressIndicator()
            else Text("Create encrypted vault")
        }
    }
}

@Composable
private fun PinUnlockScreen(
    state: VaultGateUiState,
    onUnlock: (String) -> Unit,
) {
    var pin by remember { mutableStateOf("") }
    GateColumn(
        title = "Unlock",
        description = "Enter your numeric PIN.",
        error = state.error,
    ) {
        PinField("PIN", pin) { pin = it }
        Button(
            onClick = {
                onUnlock(pin)
                pin = ""
            },
            enabled = !state.busy,
            modifier = Modifier.fillMaxWidth(),
        ) {
            if (state.busy) CircularProgressIndicator()
            else Text("Unlock")
        }
    }
}

@Composable
private fun UnlockedScreen(onLock: () -> Unit) {
    GateColumn(
        title = "Personal Authenticator",
        description = "No accounts yet. Add/import flows are the next milestone.",
        error = null,
    ) {
        Button(
            onClick = onLock,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Lock now")
        }
    }
}

@Composable
private fun GateColumn(
    title: String,
    description: String,
    error: String?,
    content: @Composable () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(title, style = MaterialTheme.typography.headlineMedium)
        Text(
            description,
            modifier = Modifier.padding(top = 12.dp, bottom = 16.dp),
            style = MaterialTheme.typography.bodyLarge,
        )
        if (error != null) {
            Text(
                error,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(bottom = 12.dp),
            )
        }
        content()
    }
}

@Composable
private fun PinField(
    label: String,
    value: String,
    onValueChange: (String) -> Unit,
) {
    OutlinedTextField(
        value = value,
        onValueChange = { replacement ->
            if (replacement.length <= 8 &&
                replacement.all { it in '0'..'9' }
            ) {
                onValueChange(replacement)
            }
        },
        label = { Text(label) },
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
        singleLine = true,
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 12.dp),
    )
}
