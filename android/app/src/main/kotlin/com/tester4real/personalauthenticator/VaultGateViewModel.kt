package com.tester4real.personalauthenticator

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.tester4real.personalauthenticator.vault.VaultSessionManager
import com.tester4real.personalauthenticator.vault.VaultSessionState
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

data class VaultGateUiState(
    val session: VaultSessionState,
    val busy: Boolean = false,
    val error: String? = null,
)

@HiltViewModel
class VaultGateViewModel @Inject constructor(
    private val sessionManager: VaultSessionManager,
) : ViewModel() {
    private val mutableUiState = MutableStateFlow(
        VaultGateUiState(sessionManager.state.value),
    )
    val uiState: StateFlow<VaultGateUiState> = mutableUiState.asStateFlow()

    init {
        viewModelScope.launch {
            sessionManager.state.collect { session ->
                mutableUiState.value = mutableUiState.value.copy(
                    session = session,
                    busy = false,
                )
            }
        }
    }

    fun setup(pin: String, confirmation: String) {
        submit {
            val pinChars = pin.toCharArray()
            val confirmationChars = confirmation.toCharArray()
            try {
                sessionManager.setup(pinChars, confirmationChars)
            } finally {
                pinChars.fill('\u0000')
                confirmationChars.fill('\u0000')
            }
        }
    }

    fun unlock(pin: String) {
        submit {
            val pinChars = pin.toCharArray()
            try {
                sessionManager.unlock(pinChars)
            } finally {
                pinChars.fill('\u0000')
            }
        }
    }

    fun lock() {
        sessionManager.lock()
    }

    fun clearError() {
        mutableUiState.value = mutableUiState.value.copy(error = null)
    }

    private fun submit(action: suspend () -> Unit) {
        if (mutableUiState.value.busy) {
            return
        }
        mutableUiState.value = mutableUiState.value.copy(
            busy = true,
            error = null,
        )
        viewModelScope.launch {
            runCatching { action() }
                .onFailure { exception ->
                    mutableUiState.value = mutableUiState.value.copy(
                        busy = false,
                        error = exception.message ?: "The operation failed.",
                    )
                }
        }
    }
}
